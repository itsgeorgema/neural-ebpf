package monitor

import "testing"

func TestIsFDLeakGrowth(t *testing.T) {
	tests := []struct {
		name    string
		history []int
		current int
		want    bool
	}{
		{
			name:    "ignores stable high descriptor baseline",
			history: []int{281, 282, 282, 283, 282},
			current: 282,
			want:    false,
		},
		{
			name:    "requires enough samples",
			history: []int{210, 260, 320, 380},
			current: 380,
			want:    false,
		},
		{
			name:    "detects rapid descriptor growth",
			history: []int{205, 260, 330, 420, 520},
			current: 520,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFDLeakGrowth(tt.history, tt.current); got != tt.want {
				t.Fatalf("isFDLeakGrowth(%v, %d) = %v, want %v", tt.history, tt.current, got, tt.want)
			}
		})
	}
}
