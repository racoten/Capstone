# Simple Weighted Graph
```go
package main

import "fmt"

// Edge represents an edge in the graph with a weight.
type Edge struct {
	To int
	Weight int
}

// WeightedGraph represents a graph where each edge has a weight.
type WeightedGraph struct {
	Edges []map[int][]Edge
	NumVertices int
}

// AddEdge adds an edge to the graph with the given weight.
func (g *WeightedGraph) AddEdge(from, to, weight int) {
	g.Edges[from][to] = append(g.Edges[from][to], Edge{To: to, Weight: weight})
}

// GetEdges returns all the edges for the given vertex.
func (g *WeightedGraph) GetEdges(vertex int) []Edge {
	edges := []Edge{}
	for to, edgeList := range g.Edges[vertex] {
		for _, edge := range edgeList {
			if edge.To == to {
				edges = append(edges, edge)
			}
		}
	}
	return edges
}

func main() {
	g := WeightedGraph{NumVertices: 3, Edges: make([]map[int][]Edge, 3)}
	for i := range g.Edges {
		g.Edges[i] = make(map[int][]Edge)
	}
	g.AddEdge(0, 1, 10)
	g.AddEdge(1, 2, 20)
	g.AddEdge(2, 0, 30)

	fmt.Println(g.GetEdges(1))
}
```

# Simple Unweighted Graph
```go
package main

import "fmt"

// Graph represents an unweighted graph.
type Graph struct {
	Edges []map[int]bool
	NumVertices int
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(from, to int) {
	g.Edges[from][to] = true
}

// HasEdge returns true if there is an edge between the given vertices.
func (g *Graph) HasEdge(from, to int) bool {
	_, ok := g.Edges[from][to]
	return ok
}

func main() {
	g := Graph{NumVertices: 3, Edges: make([]map[int]bool, 3)}
	for i := range g.Edges {
		g.Edges[i] = make(map[int]bool)
	}
	g.AddEdge(0, 1)
	g.AddEdge(1, 2)
	g.AddEdge(2, 0)

	fmt.Println(g.HasEdge(1, 2))
	fmt.Println(g.HasEdge(2, 1))
}
```

# Simple Directed Graph
```go
package main

import "fmt"

// Graph represents a directed graph.
type Graph struct {
	Edges map[int]map[int]bool
	NumVertices int
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(from, to int) {
	if g.Edges[from] == nil {
		g.Edges[from] = make(map[int]bool)
	}
	g.Edges[from][to] = true
}

// HasEdge returns true if there is an edge between the given vertices.
func (g *Graph) HasEdge(from, to int) bool {
	_, ok := g.Edges[from][to]
	return ok
}

func main() {
	g := Graph{NumVertices: 3, Edges: make(map[int]map[int]bool)}
	g.AddEdge(0, 1)
	g.AddEdge(1, 2)
	g.AddEdge(2, 0)

	fmt.Println(g.HasEdge(1, 2))
	fmt.Println(g.HasEdge(2, 1))
}
```

# Simple Undirected Graph
```go
package main

import "fmt"

// Graph represents an undirected graph.
type Graph struct {
	Edges map[int]map[int]bool
	NumVertices int
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(from, to int) {
	if g.Edges[from] == nil {
		g.Edges[from] = make(map[int]bool)
	}
	if g.Edges[to] == nil {
		g.Edges[to] = make(map[int]bool)
	}
	g.Edges[from][to] = true
	g.Edges[to][from] = true
}

// HasEdge returns true if there is an edge between the given vertices.
func (g *Graph) HasEdge(from, to int) bool {
	_, ok := g.Edges[from][to]
	return ok
}

func main() {
	g := Graph{NumVertices: 3, Edges: make(map[int]map[int]bool)}
	g.AddEdge(0, 1)
	g.AddEdge(1, 2)
	g.AddEdge(2, 0)

	fmt.Println(g.HasEdge(1, 2))
	fmt.Println(g.HasEdge(2, 1))
}
```
