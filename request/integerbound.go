package request

import (
	"math/bits"
)

// maxIntegerBoundDepth limits how deeply nested ASN.1 structures are examined.
const maxIntegerBoundDepth = 64

// integerBoundWalker scans ASN.1 (DER or BER) for INTEGERs whose magnitude
// exceeds maxBits.  Arithmetic in several linters is superlinear (in some cases
// cubic) in the size of public-key integers such as an RSA modulus or a DSA/DH
// prime, so oversized integers are rejected before any linter sees them.
//
// Parsing is deliberately lenient (non-minimal lengths, high tag numbers and
// indefinite lengths are accepted) so that an encoding quirk cannot hide an
// oversized integer from this check whilst a more forgiving linter still parses
// it.  The contents of BIT STRINGs and OCTET STRINGs are also examined, but only
// if they parse completely as ASN.1, which catches encapsulated structures such
// as an RSAPublicKey, a DSA public key, or a certificate embedded in an OCSP
// response without risking false positives from opaque binary data (e.g. an
// ML-DSA public key).
type integerBoundWalker struct {
	maxBits   int
	foundBits int
	// mustComplete is set when scanning encapsulated contents, which only count if
	// they parse completely; scanning then continues past a find, so that each byte
	// is scanned once and the cost stays linear in the input size.
	mustComplete bool
}

// findOversizedInteger returns the bit length of the first INTEGER in der whose
// magnitude exceeds maxBits, or 0 if there is none.  maxBits <= 0 disables the check.
func findOversizedInteger(der []byte, maxBits int) int {
	if maxBits <= 0 {
		return 0
	}
	w := integerBoundWalker{maxBits: maxBits}
	w.walk(der, 0, false)
	return w.foundBits
}

// walk scans a series of TLVs.  If untilEOC is true, the series is terminated by
// an end-of-contents marker.  It returns the number of bytes consumed, and
// whether b was parsed completely and successfully.
func (w *integerBoundWalker) walk(b []byte, depth int, untilEOC bool) (int, bool) {
	i := 0
	for i < len(b) {
		if untilEOC && len(b)-i >= 2 && b[i] == 0 && b[i+1] == 0 {
			return i + 2, true
		}
		n, ok := w.element(b[i:], depth)
		if !ok {
			return i, false
		} else if w.foundBits > 0 && !w.mustComplete {
			return i + n, true
		}
		i += n
	}
	return i, !untilEOC
}

// element scans one TLV, returning its total encoded length.
func (w *integerBoundWalker) element(b []byte, depth int) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	universal := b[0]&0xc0 == 0
	constructed := b[0]&0x20 != 0
	tagNumber := uint64(b[0] & 0x1f)
	i := 1
	if tagNumber == 0x1f {
		// High tag number form.
		tagNumber = 0
		for {
			if i >= len(b) || i > 9 {
				return 0, false
			}
			tagNumber = tagNumber<<7 | uint64(b[i]&0x7f)
			i++
			if b[i-1]&0x80 == 0 {
				break
			}
		}
	}

	if i >= len(b) {
		return 0, false
	}
	lengthByte := b[i]
	i++
	if lengthByte == 0x80 {
		// Indefinite length, which is only permitted for constructed encodings.
		if !constructed || depth >= maxIntegerBoundDepth {
			return 0, false
		}
		n, ok := w.walk(b[i:], depth+1, true)
		if !ok {
			return 0, false
		}
		return i + n, true
	}

	length := uint64(lengthByte)
	if lengthByte > 0x80 {
		numBytes := int(lengthByte & 0x7f)
		if numBytes > 8 || i+numBytes > len(b) {
			return 0, false
		}
		length = 0
		for _, lb := range b[i : i+numBytes] {
			length = length<<8 | uint64(lb)
		}
		i += numBytes
	}
	if length > uint64(len(b)-i) {
		return 0, false
	}
	content := b[i : i+int(length)]
	total := i + int(length)

	switch {
	case constructed:
		if depth < maxIntegerBoundDepth {
			w.walk(content, depth+1, false)
		}
	case universal && tagNumber == 2: // INTEGER.
		if n := integerBitLen(content); n > w.maxBits && w.foundBits == 0 {
			w.foundBits = n
		}
	case universal && tagNumber == 3: // BIT STRING.
		if len(content) > 1 {
			w.walkEncapsulated(content[1:], depth+1)
		}
	case universal && tagNumber == 4: // OCTET STRING.
		w.walkEncapsulated(content, depth+1)
	}

	return total, true
}

// walkEncapsulated scans the contents of a BIT STRING or OCTET STRING, but only
// reports an oversized INTEGER if the contents parse completely as ASN.1.
func (w *integerBoundWalker) walkEncapsulated(b []byte, depth int) {
	if depth >= maxIntegerBoundDepth || len(b) < 2 {
		return
	}
	sub := integerBoundWalker{maxBits: w.maxBits, mustComplete: true}
	if _, ok := sub.walk(b, depth, false); ok && sub.foundBits > 0 && w.foundBits == 0 {
		w.foundBits = sub.foundBits
	}
}

// integerBitLen returns the bit length of the magnitude of a two's complement
// big-endian integer encoding, ignoring any (non-minimal) leading padding.
func integerBitLen(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	pad := byte(0x00)
	if content[0]&0x80 != 0 {
		pad = 0xff
	}
	for len(content) > 1 && content[0] == pad {
		content = content[1:]
	}
	first := content[0]
	if pad == 0xff {
		first = ^first
	}
	return (len(content)-1)*8 + bits.Len8(first)
}
