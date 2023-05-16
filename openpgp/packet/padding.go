package packet

import "io"

// Padding type represents a Padding Packet (Tag 21).
// The padding type is represented by the length of its padding.
// see https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#name-padding-packet-tag-21
type Padding int

// parse just ignores the padding content.
func (pad Padding) parse(reader io.Reader) error {
	buffer := make([]byte, int64(pad))
	_, err := io.ReadFull(reader, buffer)
	return err
}

// SerializePadding writes the padding to writer.
func (pad Padding) SerializePadding(writer io.Writer, rand io.Reader) error {
	_, err := io.CopyN(writer, rand, int64(pad))
	return err
}