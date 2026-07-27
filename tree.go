package main

import (
	"sort"
	"strings"
)

type treeNode map[string]treeNode

func formatTree(paths []string) string {
	root := treeNode{}
	for _, path := range paths {
		node := root
		for _, part := range strings.Split(path, "/") {
			if node[part] == nil {
				node[part] = treeNode{}
			}
			node = node[part]
		}
	}
	var out strings.Builder
	appendTree(&out, root, "")
	return out.String()
}

func appendTree(out *strings.Builder, node treeNode, prefix string) {
	names := make([]string, 0, len(node))
	for name := range node {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		last := i == len(names)-1
		out.WriteString(prefix)
		if last {
			out.WriteString("└── ")
		} else {
			out.WriteString("├── ")
		}
		out.WriteString(name)
		out.WriteByte('\n')
		next := prefix + "│   "
		if last {
			next = prefix + "    "
		}
		appendTree(out, node[name], next)
	}
}
