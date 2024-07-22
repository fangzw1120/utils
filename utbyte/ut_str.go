package utbyte

import (
	"encoding/json"
	"strings"
)

// SplitStrAndRemoveEmpty 字符串根据分隔符拆分并且去空元素
func SplitStrAndRemoveEmpty(str, delimiter string) []string {
	list := strings.Split(str, delimiter)

	// 去除空元素
	var result []string
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// RemoveDuplicates 字符串slice去除重复元素
func RemoveDuplicates(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// RemoveDuplicatesGenerics 字符串slice去除重复元素
func RemoveDuplicatesGenerics[T comparable](input []T) []T {
	seen := make(map[T]bool)
	result := []T{}

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// SliceToMap slice to map[string]bool
func SliceToMap(slice []string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, item := range slice {
		result[item] = true
	}
	return result
}

func SliceToMapV1[T comparable](slice []T) map[T]interface{} {
	result := make(map[T]interface{})
	for _, item := range slice {
		result[item] = true
	}
	return result
}

func IsItemInMap[T comparable](input map[T]interface{}, i T) bool {
	_, has := input[i]
	return has
}

// MapToSlice get key slice of a map
func MapToSlice(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// MergeSliceDuplicate 合并两个slice，并且去重
func MergeSliceDuplicate(slice1, slice2 []string) []string {
	merged := append(slice1, slice2...)
	unique := make(map[string]bool)
	result := []string{}

	for _, item := range merged {
		if !unique[item] {
			unique[item] = true
			result = append(result, item)
		}
	}
	return result
}

// DeepCopy ...
func DeepCopy(src, dst interface{}) error {
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, dst)
}
