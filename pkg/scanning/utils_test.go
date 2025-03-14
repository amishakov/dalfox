package scanning

import (
	"testing"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

func Test_indexOf(t *testing.T) {
	type args struct {
		element string
		data    []string
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "Element found",
			args: args{element: "b", data: []string{"a", "b", "c"}},
			want: 1,
		},
		{
			name: "Element not found",
			args: args{element: "d", data: []string{"a", "b", "c"}},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := indexOf(tt.args.element, tt.args.data); got != tt.want {
				t.Errorf("indexOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_duplicatedResult(t *testing.T) {
	type args struct {
		result []model.PoC
		rst    model.PoC
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Duplicate found",
			args: args{
				result: []model.PoC{{Type: "type1"}, {Type: "type2"}},
				rst:    model.PoC{Type: "type1"},
			},
			want: true,
		},
		{
			name: "Duplicate not found",
			args: args{
				result: []model.PoC{{Type: "type1"}, {Type: "type2"}},
				rst:    model.PoC{Type: "type3"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := duplicatedResult(tt.args.result, tt.args.rst); got != tt.want {
				t.Errorf("duplicatedResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containsFromArray(t *testing.T) {
	type args struct {
		slice []string
		item  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Item found",
			args: args{slice: []string{"a", "b", "c"}, item: "b"},
			want: true,
		},
		{
			name: "Item not found",
			args: args{slice: []string{"a", "b", "c"}, item: "d"},
			want: false,
		},
		{
			name: "Item found with parentheses",
			args: args{slice: []string{"a", "b", "c"}, item: "b(something)"},
			want: true,
		},
		{
			name: "Item not found with parentheses",
			args: args{slice: []string{"a", "b", "c"}, item: "d(something)"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsFromArray(tt.args.slice, tt.args.item); got != tt.want {
				t.Errorf("containsFromArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkPType(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid type",
			args: args{str: "validType"},
			want: true,
		},
		{
			name: "Invalid type toBlind",
			args: args{str: "toBlind"},
			want: false,
		},
		{
			name: "Invalid type toGrepping",
			args: args{str: "toGrepping"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPType(tt.args.str); got != tt.want {
				t.Errorf("checkPType() = %v, want %v", got, tt.want)
			}
		})
	}
}
