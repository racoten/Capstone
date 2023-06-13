# Simple Queue Data Structure
```go
type Queue struct {
    items []int
}

func (q *Queue) Enqueue(item int) {
    q.items = append(q.items, item)
}

func (q *Queue) Dequeue() int {
    item := q.items[0]
    q.items = q.items[1:]
    return item
}

func (q *Queue) IsEmpty() bool {
    return len(q.items) == 0
}

func (q *Queue) Size() int {
    return len(q.items)
}
```

# Circular Queue
```go
type CircularQueue struct {
    items []int
    head int
    tail int
    size int
}

func (cq *CircularQueue) Enqueue(item int) {
    if cq.size == len(cq.items) {
        cq.resize()
    }
    cq.items[cq.tail] = item
    cq.tail = (cq.tail + 1) % len(cq.items)
    cq.size++
}

func (cq *CircularQueue) Dequeue() int {
    if cq.IsEmpty() {
        panic("Cannot dequeue from an empty queue")
    }
    item := cq.items[cq.head]
    cq.head = (cq.head + 1) % len(cq.items)
    cq.size--
    return item
}

func (cq *CircularQueue) IsEmpty() bool {
    return cq.size == 0
}

func (cq *CircularQueue) Size() int {
    return cq.size
}

func (cq *CircularQueue) resize() {
    newItems := make([]int, 2*len(cq.items))
    for i := 0; i < cq.size; i++ {
        newItems[i] = cq.items[(cq.head+i)%len(cq.items)]
    }
    cq.items = newItems
    cq.head = 0
    cq.tail = cq.size
}
```

# Priority Queue
```go
type Item struct {
    value    interface{}
    priority int
    index    int
}

type PriorityQueue []*Item

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
    return pq[i].priority < pq[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
    pq[i], pq[j] = pq[j], pq[i]
    pq[i].index = i
    pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
    n := len(*pq)
    item := x.(*Item)
    item.index = n
    *pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
    old := *pq
    n := len(old)
    item := old[n-1]
    item.index = -1 // for safety
    *pq = old[0 : n-1]
    return item
}

// update modifies the priority and value of an Item in the queue.
func (pq *PriorityQueue) update(item *Item, value interface{}, priority int) {
    item.value = value
    item.priority = priority
    heap.Fix(pq, item.index)
}
```

# Double Ended Queue (deque)
```go
type Deque struct {
    items []int
    head int
    tail int
    size int
}

func (d *Deque) PushFront(item int) {
    if d.size == len(d.items) {
        d.resize()
    }
    d.head = (d.head - 1 + len(d.items)) % len(d.items)
    d.items[d.head] = item
    d.size++
}

func (d *Deque) PushBack(item int) {
    if d.size == len(d.items) {
        d.resize()
    }
    d.items[d.tail] = item
    d.tail = (d.tail + 1) % len(d.items)
    d.size++
}

func (d *Deque) PopFront() int {
    if d.IsEmpty() {
        panic("Cannot pop from an empty deque")
    }
    item := d.items[d.head]
    d.head = (d.head + 1) % len(d.items)
    d.size--
    return item
}

func (d *Deque) PopBack() int {
    if d.IsEmpty() {
        panic("Cannot pop from an empty deque")
    }
    d.tail = (d.tail - 1 + len(d.items)) % len(d.items)
    item := d.items[d.tail]
    d.size--
    return item
}

func (d *Deque) IsEmpty() bool {
    return d.size == 0
}

func (d *Deque) resize() {
    newItems := make([]int, 2*len(d.items))
    for i := 0; i < d.size; i++ {
        newItems[i] = d.items[(d.head+i)%len(d.items)]
    }
    d.items = newItems
    d.head = 0
    d.tail = d.size
}
```
