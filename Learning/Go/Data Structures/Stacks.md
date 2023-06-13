# Simple Stack Data Structure
```go
type Stack struct {
    items []int
}

func (s *Stack) Push(item int) {
    s.items = append(s.items, item)
}

func (s *Stack) Pop() int {
    item := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return item
}

func (s *Stack) IsEmpty() bool {
    return len(s.items) == 0
}

func (s *Stack) Peek() int {
    return s.items[len(s.items)-1]
}

func (s *Stack) Size() int {
    return len(s.items)
}
```
