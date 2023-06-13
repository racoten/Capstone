# Simple Binary Tree
```go
type Node struct {
    Value int
    Left *Node
    Right *Node
}

type BinaryTree struct {
    Root *Node
}

func (b *BinaryTree) Insert(value int) {
    newNode := &Node{Value: value}

    if b.Root == nil {
        b.Root = newNode
        return
    }

    currentNode := b.Root
    for {
        if value < currentNode.Value {
            if currentNode.Left == nil {
                currentNode.Left = newNode
                return
            }
            currentNode = currentNode.Left
        } else {
            if currentNode.Right == nil {
                currentNode.Right = newNode
                return
            }
            currentNode = currentNode.Right
        }
    }
}

func (b *BinaryTree) Search(value int) bool {
    currentNode := b.Root
    for currentNode != nil {
        if value == currentNode.Value {
            return true
        } else if value < currentNode.Value {
            currentNode = currentNode.Left
        } else {
            currentNode = currentNode.Right
        }
    }
    return false
}
```

# Simple Binary Search Tree
```go
type Node struct {
    Value int
    Left *Node
    Right *Node
}

type BinarySearchTree struct {
    Root *Node
}

func (b *BinarySearchTree) Insert(value int) {
    newNode := &Node{Value: value}

    if b.Root == nil {
        b.Root = newNode
        return
    }

    currentNode := b.Root
    for {
        if value < currentNode.Value {
            if currentNode.Left == nil {
                currentNode.Left = newNode
                return
            }
            currentNode = currentNode.Left
        } else {
            if currentNode.Right == nil {
                currentNode.Right = newNode
                return
            }
            currentNode = currentNode.Right
        }
    }
}

func (b *BinarySearchTree) Search(value int) bool {
    currentNode := b.Root
    for currentNode != nil {
        if value == currentNode.Value {
            return true
        } else if value < currentNode.Value {
            currentNode = currentNode.Left
        } else {
            currentNode = currentNode.Right
        }
    }
    return false
}
```
