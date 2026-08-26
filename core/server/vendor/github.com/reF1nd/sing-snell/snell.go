package snell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	M "github.com/sagernet/sing/common/metadata"

	snellinternal "github.com/reF1nd/sing-snell/internal"
)

// ErrZeroChunk is returned by the stream/v4 readers when a zero-length frame
// is received. It signals the end of one sub-stream in a reuse session.
// Callers that implement connection reuse (PoolConn, reuseClientConn) convert
// this into io.EOF for the application layer.
var ErrZeroChunk = snellinternal.ErrZeroChunk

const (
	Version1 = snellinternal.Version1
	Version2 = snellinternal.Version2
	Version3 = snellinternal.Version3
	Version4 = snellinternal.Version4
	Version5 = snellinternal.Version5

	// DefaultVersion is v4: the most widely deployed version and the only one
	// supported by mihomo's server. Set explicitly if you need v1–v3.
	DefaultVersion = snellinternal.DefaultVersion

	maxPacketSize = snellinternal.MaxPacketSize
)

// PacketFrameWriter is implemented by connections that must write each UDP
// packet as a single atomic frame (required for v4/v5 so that the reader
// can reconstruct the full packet with a single Read call).
type PacketFrameWriter interface {
	WritePacketFrame([]byte) (int, error)
}

const (
	CommandPing      byte = 0
	CommandConnect   byte = 1
	CommandConnectV2 byte = 5
	CommandUDP       byte = 6

	CommandTunnel     byte = 0
	CommandPong       byte = 1
	CommandError      byte = 2
	CommandUDPForward byte = 1

	ProtocolVersion byte = 1
)

// WriteHeader writes the Snell TCP request header (CommandConnect).
func WriteHeader(w io.Writer, host string, port uint16, version int) error {
	return WriteHeaderWithReuse(w, host, port, version, false)
}

// WriteHeaderWithReuse writes the Snell TCP request header.
// When reuse is true (v4 connection reuse), CommandConnectV2 is used so the
// server knows to keep the connection alive for subsequent requests.
func WriteHeaderWithReuse(w io.Writer, host string, port uint16, version int, reuse bool) error {
	buf := make([]byte, 0, 8+len(host))
	buf = append(buf, ProtocolVersion)
	if version == Version2 || reuse {
		buf = append(buf, CommandConnectV2)
	} else {
		buf = append(buf, CommandConnect)
	}
	buf = append(buf, 0) // clientID length = 0
	buf = append(buf, byte(len(host)))
	buf = append(buf, host...)
	buf = binary.BigEndian.AppendUint16(buf, port)
	_, err := w.Write(buf)
	return err
}

// WriteUDPHeader writes the Snell UDP request header (v3+).
func WriteUDPHeader(w io.Writer) error {
	_, err := w.Write([]byte{ProtocolVersion, CommandUDP, 0x00})
	return err
}

// ReadServerReply reads the server's reply byte after a request.
// On success (CommandTunnel=0), nil is returned.
func ReadServerReply(r io.Reader) error {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	switch buf[0] {
	case CommandTunnel:
		return nil
	case CommandError:
		var codeBuf [1]byte
		if _, err := io.ReadFull(r, codeBuf[:]); err != nil {
			return err
		}
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return err
		}
		msg := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		return fmt.Errorf("snell: server error %d: %s", codeBuf[0], msg)
	default:
		return fmt.Errorf("snell: unexpected reply command: %d", buf[0])
	}
}

// WriteServerReply writes a success response to the client.
func WriteServerReply(w io.Writer) error {
	_, err := w.Write([]byte{CommandTunnel})
	return err
}

// WriteServerError writes an error response to the client.
func WriteServerError(w io.Writer, code byte, message string) error {
	msg := []byte(message)
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, CommandError, code, byte(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// WriteUDPPacket writes a UDP packet in the Snell UDP format.
// For v4/v5 connections (which implement PacketFrameWriter), the entire packet
// is written as a single atomic frame so the peer can read it back whole.
func WriteUDPPacket(w io.Writer, addr net.Addr, payload []byte) (int, error) {
	socks5Addr := marshalAddr(addr)
	if socks5Addr == nil {
		return 0, errors.New("snell: unsupported address type")
	}
	buf := make([]byte, 0, 1+len(socks5Addr)+len(payload))
	buf = append(buf, CommandUDPForward)
	buf = append(buf, socks5Addr...)
	buf = append(buf, payload...)
	if fw, ok := w.(PacketFrameWriter); ok {
		_, err := fw.WritePacketFrame(buf)
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	_, err := w.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// WriteUDPResponse writes a UDP response in the Snell UDP response format.
// For v4/v5 connections (which implement PacketFrameWriter), the entire
// response is written as a single atomic frame.
func WriteUDPResponse(w io.Writer, addr net.Addr, payload []byte) (int, error) {
	ip, port, err := parseNetAddr(addr)
	if err != nil {
		return 0, err
	}
	var buf []byte
	if ip4 := ip.To4(); ip4 != nil {
		buf = make([]byte, 0, 1+net.IPv4len+2+len(payload))
		buf = append(buf, 0x04)
		buf = append(buf, ip4...)
	} else {
		buf = make([]byte, 0, 1+net.IPv6len+2+len(payload))
		buf = append(buf, 0x06)
		buf = append(buf, ip...)
	}
	buf = binary.BigEndian.AppendUint16(buf, port)
	buf = append(buf, payload...)
	if fw, ok := w.(PacketFrameWriter); ok {
		_, err := fw.WritePacketFrame(buf)
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	_, err = w.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// WriteSocksaddrUDPResponse writes a Snell UDP response frame to w.
// Unlike WriteUDPResponse, it accepts a M.Socksaddr so domain-name source
// addresses are encoded correctly:
//
//	0x03 [len:1] [domain bytes] [port:2] [payload]  — domain
//	0x04 [IPv4:4]               [port:2] [payload]  — IPv4
//	0x06 [IPv6:16]              [port:2] [payload]  — IPv6
func WriteSocksaddrUDPResponse(w io.Writer, addr M.Socksaddr, payload []byte) (int, error) {
	var buf []byte
	if addr.IsFqdn() {
		host := addr.Fqdn
		if len(host) > 255 {
			return 0, errors.New("snell: domain name too long for UDP response")
		}
		buf = make([]byte, 0, 2+len(host)+2+len(payload))
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	} else if addr.Addr.Is4() || addr.Addr.Is4In6() {
		ip4 := addr.Addr.As4()
		buf = make([]byte, 0, 1+net.IPv4len+2+len(payload))
		buf = append(buf, 0x04)
		buf = append(buf, ip4[:]...)
	} else if addr.Addr.Is6() {
		ip6 := addr.Addr.As16()
		buf = make([]byte, 0, 1+net.IPv6len+2+len(payload))
		buf = append(buf, 0x06)
		buf = append(buf, ip6[:]...)
	} else {
		return 0, errors.New("snell: invalid address for UDP response")
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	buf = append(buf, payload...)
	if fw, ok := w.(PacketFrameWriter); ok {
		_, err := fw.WritePacketFrame(buf)
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	_, err := w.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// UDPRequest represents a parsed Snell UDP request.
type UDPRequest struct {
	Host    string
	IP      net.IP
	Port    uint16
	Payload []byte
}

// ParseUDPRequest parses a Snell UDP request packet.
func ParseUDPRequest(packet []byte) (UDPRequest, error) {
	if len(packet) < 2 || packet[0] != CommandUDPForward {
		return UDPRequest{}, errors.New("snell: invalid UDP request")
	}
	if hostLen := int(packet[1]); hostLen != 0 {
		end := 2 + hostLen + 2
		if len(packet) <= end {
			return UDPRequest{}, errors.New("snell: invalid UDP domain request")
		}
		return UDPRequest{
			Host:    string(packet[2 : 2+hostLen]),
			Port:    binary.BigEndian.Uint16(packet[2+hostLen : end]),
			Payload: packet[end:],
		}, nil
	}
	if len(packet) < 3 {
		return UDPRequest{}, errors.New("snell: invalid UDP IP request")
	}
	switch packet[2] {
	case 0x04:
		offset := 3 + net.IPv4len
		if len(packet) < offset+2 {
			return UDPRequest{}, errors.New("snell: invalid UDP IPv4 request")
		}
		return UDPRequest{
			IP:      append(net.IP{}, packet[3:offset]...),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	case 0x06:
		offset := 3 + net.IPv6len
		if len(packet) < offset+2 {
			return UDPRequest{}, errors.New("snell: invalid UDP IPv6 request")
		}
		return UDPRequest{
			IP:      append(net.IP{}, packet[3:offset]...),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	default:
		return UDPRequest{}, errors.New("snell: invalid UDP address type")
	}
}

// WriteSocksaddrUDPPacket writes a UDP packet to w using the Snell UDP request
// format. Unlike WriteUDPPacket, it accepts a M.Socksaddr so domain-name
// destinations are encoded correctly as the Snell protocol requires.
func WriteSocksaddrUDPPacket(w io.Writer, addr M.Socksaddr, payload []byte) (int, error) {
	buf := make([]byte, 0, 4+len(addr.Fqdn)+2+len(payload))
	buf = append(buf, CommandUDPForward)
	if addr.IsFqdn() {
		host := addr.Fqdn
		if len(host) > 255 {
			return 0, errors.New("snell: domain name too long for UDP")
		}
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	} else if addr.Addr.Is4() || addr.Addr.Is4In6() {
		ip4 := addr.Addr.As4()
		buf = append(buf, 0x00, 0x04)
		buf = append(buf, ip4[:]...)
	} else if addr.Addr.Is6() {
		ip6 := addr.Addr.As16()
		buf = append(buf, 0x00, 0x06)
		buf = append(buf, ip6[:]...)
	} else {
		return 0, errors.New("snell: invalid address for UDP packet")
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	buf = append(buf, payload...)
	if fw, ok := w.(PacketFrameWriter); ok {
		_, err := fw.WritePacketFrame(buf)
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	_, err := w.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func marshalAddr(addr net.Addr) []byte {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return marshalIP(a.IP, uint16(a.Port))
	case *net.UDPAddr:
		return marshalIP(a.IP, uint16(a.Port))
	default:
		return nil
	}
}

func marshalIP(ip net.IP, port uint16) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		buf := make([]byte, 0, 2+net.IPv4len+2)
		buf = append(buf, 0x00, 0x04)
		buf = append(buf, ip4...)
		buf = binary.BigEndian.AppendUint16(buf, port)
		return buf
	}
	buf := make([]byte, 0, 2+net.IPv6len+2)
	buf = append(buf, 0x00, 0x06)
	buf = append(buf, ip...)
	buf = binary.BigEndian.AppendUint16(buf, port)
	return buf
}

func parseNetAddr(addr net.Addr) (net.IP, uint16, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP, uint16(a.Port), nil
	case *net.UDPAddr:
		return a.IP, uint16(a.Port), nil
	default:
		return nil, 0, errors.New("snell: unsupported address type")
	}
}
