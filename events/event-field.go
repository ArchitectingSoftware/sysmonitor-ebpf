package events

type FieldType uint8

const (
	UnknownType FieldType = iota
	ArrayType
	StringType
	Uint32Type
	Uint64Type
)

type EventField struct {
	Key       string
	Type      FieldType
	Interface interface{}
	String    string
	Number    int64
}

type uint64a []uint64

func (nums uint64a) MarshalEventArray(arr ArrayEncoder) error {
	return nil
}

type uint32a []uint32

func (nums uint32a) MarshalEventArray(arr ArrayEncoder) error {
	return nil
}
