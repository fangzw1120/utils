package utbyte

import (
	"database/sql"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// NullableTimestamp ...
type NullableTimestamp struct {
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	IsNull    bool                   `protobuf:"varint,2,opt,name=is_null,json=isNull,proto3" json:"is_null,omitempty"`
}

// ToNullableTimestamp ...
func ToNullableTimestamp(t sql.NullTime) *NullableTimestamp {
	if !t.Valid {
		return &NullableTimestamp{IsNull: true}
	}
	return &NullableTimestamp{
		Timestamp: &timestamppb.Timestamp{
			Seconds: t.Time.Unix(),
			Nanos:   int32(t.Time.Nanosecond()),
		},
		IsNull: false,
	}
}

// TimeToNullableTimestamp ...
func TimeToNullableTimestamp(t time.Time) *NullableTimestamp {
	if t.IsZero() {
		return &NullableTimestamp{IsNull: true}
	}
	return &NullableTimestamp{
		Timestamp: &timestamppb.Timestamp{
			Seconds: t.Unix(),
			Nanos:   int32(t.Nanosecond()),
		},
		IsNull: false,
	}
}

// FromNullableTimestampToTime ...
func FromNullableTimestampToTime(nt *NullableTimestamp) time.Time {
	if nt.IsNull {
		return time.Time{}
	}
	t := time.Unix(nt.Timestamp.Seconds, int64(nt.Timestamp.Nanos))
	return t
}

// FromNullableTimestamp ...
func FromNullableTimestamp(nt *NullableTimestamp) sql.NullTime {
	if nt.IsNull {
		return sql.NullTime{Valid: false}
	}
	t := time.Unix(nt.Timestamp.Seconds, int64(nt.Timestamp.Nanos))
	return sql.NullTime{Time: t, Valid: true}
}

// ConvertFloat64ToTime 将 float64 类型的时间戳转换为 int64 类型
func ConvertFloat64ToTime(timestamp float64) time.Time {
	unixTimestamp := int64(timestamp)

	// 使用 time.Unix() 函数将 int64 类型的时间戳转换为 time.Time 类型的时间
	t := time.Unix(unixTimestamp, 0)
	return t
}
