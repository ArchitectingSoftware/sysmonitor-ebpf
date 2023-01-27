package events

type ArrayEncoder struct {
	AppendUint32 (uint32)
	AppendUint64 (uint64)
}
type ArrayMarshalerFunc func(ArrayEncoder) error

type ArrayMarshaler interface {
	MarshalEventArray(ArrayEncoder) error
}

func (f ArrayMarshalerFunc) MarshalEventArray(enc ArrayEncoder) error {
	return f(enc)
}

func Array(key string, val ArrayMarshaler) EventField {
	return EventField{Key: key, Type: ArrayType, Interface: val}
}

func Uint32a(key string, nums []uint32) EventField {
	return Array(key, uint32a(nums))
}

func Uint64a(key string, nums []uint64) EventField {
	return Array(key, uint64a(nums))
}

func String(key string, val string) EventField {
	return EventField{Key: key, Type: StringType, String: val}
}

func Unknown(key string, val interface{}) EventField {
	return EventField{Key: key, Type: UnknownType, Interface: val}
}

func Any(key string, value interface{}) EventField {
	switch val := value.(type) {
	case ArrayMarshaler:
		return Array(key, val)
	case string:
		return String(key, val)
	case []uint32:
		return Uint32a(key, val)
	case []uint64:
		return Uint64a(key, val)
	default:
		return Unknown(key, val)
	}
}
