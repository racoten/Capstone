# Single LinkedList in Go
```go
type Node struct {
    Value int
    Next *Node
}

type LinkedList struct {
    Head *Node
}

func (l *LinkedList) InsertAfter(node *Node, value int) {
    newNode := &Node{Value: value}
    newNode.Next = node.Next
    node.Next = newNode
}

func (l *LinkedList) Append(value int) {
    newNode := &Node{Value: value}

    if l.Head == nil {
        l.Head = newNode
        return
    }

    currentNode := l.Head
    for currentNode.Next != nil {
        currentNode = currentNode.Next
    }
    currentNode.Next = newNode
}

func (l *LinkedList) Prepend(value int) {
    newNode := &Node{Value: value}
    newNode.Next = l.Head
    l.Head = newNode
}

func (l *LinkedList) Delete(value int) {
    if l.Head == nil {
        return
    }

    if l.Head.Value == value {
        l.Head = l.Head.Next
        return
    }

    currentNode := l.Head
    for currentNode.Next != nil {
        if currentNode.Next.Value == value {
            currentNode.Next = currentNode.Next.Next
            return
        }
        currentNode = currentNode.Next
    }
}
```

# Circular LinkedList in Go
```go
type Node struct {
    Value int
    Next *Node
}

type CircularLinkedList struct {
    Head *Node
}

func (c *CircularLinkedList) InsertAfter(node *Node, value int) {
    newNode := &Node{Value: value}
    newNode.Next = node.Next
    node.Next = newNode
}

func (c *CircularLinkedList) Append(value int) {
    newNode := &Node{Value: value}

    if c.Head == nil {
        c.Head = newNode
        newNode.Next = c.Head
        return
    }

    currentNode := c.Head
    for currentNode.Next != c.Head {
        currentNode = currentNode.Next
    }
    currentNode.Next = newNode
    newNode.Next = c.Head
}

func (c *CircularLinkedList) Prepend(value int) {
    newNode := &Node{Value: value}
    newNode.Next = c.Head
    currentNode := c.Head

    if c.Head == nil {
        c.Head = newNode
        newNode.Next = c.Head
        return
    }

    for currentNode.Next != c.Head {
        currentNode = currentNode.Next
    }
    currentNode.Next = newNode
    c.Head = newNode
}

func (c *CircularLinkedList) Delete(value int) {
    if c.Head == nil {
        return
    }

    if c.Head.Value == value {
        currentcurrentNode := c.Head
    for currentNode.Next != c.Head {
        if currentNode.Next.Value == value {
            currentNode.Next = currentNode.Next.Next
            return
        }
        currentNode = currentNode.Next
    }

    if currentNode.Value == value {
        currentNode.Next = currentNode.Next.Next
        c.Head = currentNode.Next
    }
}
```

# Doubly LinkedList
```go
type Node struct {
    Value int
    Prev *Node
    Next *Node
}

type DoublyLinkedList struct {
    Head *Node
    Tail *Node
}

func (d *DoublyLinkedList) InsertAfter(node *Node, value int) {
    newNode := &Node{Value: value}
    newNode.Prev = node
    newNode.Next = node.Next
    node.Next = newNode
}

func (d *DoublyLinkedList) Append(value int) {
    newNode := &Node{Value: value}

    if d.Head == nil {
        d.Head = newNode
        d.Tail = newNode
        return
    }

    d.Tail.Next = newNode
    newNode.Prev = d.Tail
    d.Tail = newNode
}

func (d *DoublyLinkedList) Prepend(value int) {
    newNode := &Node{Value: value}

    if d.Head == nil {
        d.Head = newNode
        d.Tail = newNode
        return
    }

    d.Head.Prev = newNode
    newNode.Next = d.Head
    d.Head = newNode
}

func (d *DoublyLinkedList) Delete(value int) {
    currentNode := d.Head
    for currentNode != nil {
        if currentNode.Value == value {
            currentNode.Prev.Next = currentNode.Next
            currentNode.Next.Prev = currentNode.Prev
            return
        }
        currentNode = currentNode.Next
    }
}
```
