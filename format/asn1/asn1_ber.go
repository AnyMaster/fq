package asn1

// T-REC-X.690-200811 (BER, DER, CER)
// https://en.wikipedia.org/wiki/X.690
// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
// https://luca.ntop.org/Teaching/Appunti/asn1.html

// TODO: gammar/schema?
// TODO: der/cer via mode?
// TODO: torepr
// TODO: oids
// TODO: more types?
// TODO: constructed strings etc

import (
	"bytes"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/bitio"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
)

// //go:embed *.jq
// var asn1FS embed.FS

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.ASN1_BER,
		Description: "ASN1 Basic Encoding Rules",
		DecodeFn:    decodeASN1BER,
		// Files:       asn1FS,
		// ToRepr:      "_asn1_torepr",
	})
}

const (
	classUniversal   = 0b00
	classApplication = 0b01
	classContext     = 0b10
	classPrivate     = 0b11
)

var tagClassMap = scalar.UToSymStr{
	classUniversal:   "universal",
	classApplication: "application",
	classContext:     "context",
	classPrivate:     "private",
}

const (
	formPrimitive   = 0
	formConstructed = 1
)

var constructedPrimitiveMap = scalar.UToSymStr{
	formConstructed: "constructed",
	formPrimitive:   "primitive",
}

const (
	universalTypeEndOfContent     = 0x00
	universalTypeBoolean          = 0x01
	universalTypeInteger          = 0x02
	universalTypeBitString        = 0x03
	universalTypeOctetString      = 0x04
	universalTypeNull             = 0x05
	universalTypeObjectIdentifier = 0x06
	universalTypeObjectDescriptor = 0x07 // not encoded, just documentation?
	universalTypeExternal         = 0x08
	universalTypeReal             = 0x09
	universalTypeEnumerated       = 0x0a
	universalTypeEmbedded         = 0x0b
	universalTypeUTF8string       = 0x0c
	universalTypeSequence         = 0x10
	universalTypeSet              = 0x11
	universalTypeNumericString    = 0x12
	universalTypePrintableString  = 0x13
	universalTypeTeletexString    = 0x14
	universalTypeVideotexString   = 0x15
	universalTypeIA5String        = 0x16
	universalTypeUTCTime          = 0x17
	universalTypeGeneralizedtime  = 0x18
	universalTypeGraphicString    = 0x19 // not encoded?
	universalTypeVisibleString    = 0x1a
	universalTypeGeneralString    = 0x1b
	universalTypeUniversalString  = 0x1c // not encoded?
)

var universalTypeMap = scalar.UToSymStr{
	universalTypeEndOfContent:     "end_of_content",
	universalTypeBoolean:          "boolean",
	universalTypeInteger:          "integer",
	universalTypeBitString:        "bit_string",
	universalTypeOctetString:      "octet_string",
	universalTypeNull:             "null",
	universalTypeObjectIdentifier: "object_identifier",
	universalTypeObjectDescriptor: "object_descriptor",
	universalTypeExternal:         "external",
	universalTypeReal:             "real",
	universalTypeEnumerated:       "enumerated",
	universalTypeEmbedded:         "embedded",
	universalTypeUTF8string:       "utf8_string",
	universalTypeSequence:         "sequence",
	universalTypeSet:              "set",
	universalTypeNumericString:    "numeric_string",
	universalTypePrintableString:  "printable_string",
	universalTypeTeletexString:    "teletex_string",
	universalTypeVideotexString:   "videotex_string",
	universalTypeIA5String:        "ia5_string",
	universalTypeUTCTime:          "utc_time",
	universalTypeGeneralizedtime:  "generalized_time",
	universalTypeGraphicString:    "graphic_string",
	universalTypeVisibleString:    "visible_string",
	universalTypeGeneralString:    "general_string",
	universalTypeUniversalString:  "universal_string",
}

const (
	lengthIndefinite = 0
	lengthEndMarker  = 0x00_00
)

var lengthMap = scalar.UToSymStr{
	0: "indefinite",
}

func decodeLength(d *decode.D) uint64 {
	n := d.U8()
	if n&0b1000_0000 != 0 {
		n = n & 0b0111_1111
		if n == 0 {
			return lengthIndefinite
		}
		if n == 127 {
			d.Errorf("length 127 reserved")
		}
		// TODO: bigint
		return d.U(int(n) * 8)
	}
	return n & 0b0111_1111
}

// TODO: bigint?
func decodeTagNumber(d *decode.D) uint64 {
	v := d.U5()
	moreBytes := v == 0b11111
	for moreBytes {
		moreBytes = d.Bool()
		v = v<<7 | d.U7()
	}
	return v
}

func decodeASN1BERValue(d *decode.D, bb *bytes.Buffer, parentForm uint64, parentTag uint64) interface{} {
	class := d.FieldU2("class", tagClassMap)
	form := d.FieldU1("form", constructedPrimitiveMap)

	var tag uint64
	switch class {
	case classUniversal:
		tag = d.FieldUFn("tag", decodeTagNumber, universalTypeMap, scalar.Hex)
	default:
		tag = d.FieldUFn("tag", decodeTagNumber)
	}

	length := d.FieldUFn("length", decodeLength, lengthMap)
	l := d.BitsLeft()
	if length != lengthIndefinite {
		l = int64(length) * 8
	}

	d.LenFn(l, func(d *decode.D) {
		switch {
		case form == formConstructed || tag == universalTypeSequence || tag == universalTypeSet:
			constructedRoot := bb == nil
			d.FieldArray("constructed", func(d *decode.D) {
				for !d.End() {
					if length == lengthIndefinite && d.PeekBits(16) == lengthEndMarker {
						break
					}
					if bb == nil && (tag == universalTypeBitString || tag == universalTypeUTF8string) {
						bb = &bytes.Buffer{}
					}
					d.FieldStruct("object", func(d *decode.D) { decodeASN1BERValue(d, bb, form, tag) })
				}
			})
			if length == lengthIndefinite {
				d.FieldU16("end_marker")
			}
			if constructedRoot {
				switch tag {
				case universalTypeBitString:
					d.FieldRootBitBuf("value", bitio.NewBufferFromBytes(bb.Bytes(), -1))
				}
			}
		case class == classUniversal && tag == universalTypeEndOfContent:
			// nop
		case class == classUniversal && tag == universalTypeBoolean:
			d.FieldU8("value", scalar.URangeToScalar{
				{Range: [2]uint64{0, 0}, S: scalar.S{Sym: false}},
				{Range: [2]uint64{0x01, 0xff1}, S: scalar.S{Sym: true}},
			})
		case class == classUniversal && tag == universalTypeInteger:
			if length > 8 {
				d.FieldUBigInt("value", int(length)*8)
			} else {
				d.FieldU("value", int(length)*8)
			}
		case class == classUniversal && tag == universalTypeBitString:
			unusedBitsCount := d.FieldU8("unused_bits_count")
			// TODO: unusedBitsCount 0-7
			bib := d.FieldRawLen("value", int64(length-1)*8-int64(unusedBitsCount))
			if bb != nil {
				bs, err := bib.Bytes()
				if err != nil {
					d.IOPanic(err, "BitString bytes")
				}
				// TODO: need bits buffer
				bb.Write(bs)
			}
			if unusedBitsCount > 0 {
				d.FieldRawLen("unused_bits", int64(unusedBitsCount))
			}
		case class == classUniversal && tag == universalTypeOctetString:
			d.FieldUTF8("value", int(length))
		case class == classUniversal && tag == universalTypeNull:
			d.FieldValueNil("value")
		case class == classUniversal && tag == universalTypeObjectIdentifier:
			// TODO (X*40) + Y thingy?
			d.FieldArray("oids", func(d *decode.D) {
				for !d.End() {
					d.FieldUFn("oid", func(d *decode.D) uint64 {
						more := true
						var n uint64
						for more {
							b := d.U8()
							n = n<<7 | b&0b0111_1111
							more = b&0b1000_0000 != 0
						}
						return n
					})
				}
			})
		case class == classUniversal && tag == universalTypeObjectDescriptor: // not encoded,just documentation?
			// nop
		case class == classUniversal && tag == universalTypeExternal:
			d.FieldRawLen("value", int64(length)*8)
		case class == classUniversal && tag == universalTypeReal:
			switch {
			case length == 0:
				d.FieldValueU("value", 0)
			default:
				switch d.FieldBool("binary_encoding") {
				case true:
					sign := d.FieldScalarBool("sign", scalar.BoolToSymS{
						true:  -1,
						false: 1,
					}).SymS()
					base := d.FieldScalarU2("base", scalar.UToSymU{
						0b00: 2,
						0b01: 8,
						0b10: 16,
						0b11: 0,
					}).SymU()
					scale := d.FieldU2("scale")
					format := d.FieldU2("format")
					n := d.FieldUBigInt("n", int(d.BitsLeft()))

					_ = sign
					_ = base
					_ = scale
					_ = format
					_ = n

				case false:
					switch d.FieldBool("decimal_encoding") {
					case true:
						d.FieldU6("representation", scalar.UToSymStr{
							0b00_0001: "nr1",
							0b00_0010: "nr2",
							0b00_0011: "nr3",
						})
						d.FieldUBigInt("n", int(d.BitsLeft()))
					case false:
						d.FieldU6("special", scalar.UToSymStr{
							0b0100_0000: "plus_infinity",
							0b0100_0001: "minus_infinity",
							0b0100_0010: "nan",
							0b0100_0011: "minus_zero",
						})
					}
				}

				// TODO: value?
			}
		case class == classUniversal && tag == universalTypeUTF8string:
			d.FieldUTF8("value", int(length))
		case class == classUniversal && tag == universalTypeNumericString,
			class == classUniversal && tag == universalTypePrintableString,
			class == classUniversal && tag == universalTypeTeletexString,
			class == classUniversal && tag == universalTypeVideotexString,
			class == classUniversal && tag == universalTypeIA5String,
			class == classUniversal && tag == universalTypeVisibleString, // not encoded?
			class == classUniversal && tag == universalTypeGeneralString: // not encoded?
			// TODO: restrict?
			d.FieldUTF8("value", int(length))
		case class == classUniversal && tag == universalTypeUTCTime:
			d.FieldRawLen("value", int64(length)*8)
		case class == classUniversal && tag == universalTypeGeneralizedtime:
			d.FieldRawLen("value", int64(length)*8)
		default:
			d.FieldRawLen("value", l)
		}
	})

	return nil
}

func decodeASN1BER(d *decode.D, in interface{}) interface{} {
	decodeASN1BERValue(d, nil, formConstructed, universalTypeSequence)
	return nil
}
