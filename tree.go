package main

import (
	"sort"
	"strings"
)

type treeNode map[string]treeNode

func formatTree(paths []string) string {
	return formatTreeWithTheme(paths, cliTheme{})
}

func formatTreeWithTheme(paths []string, theme cliTheme) string {
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
	appendTree(&out, root, "", 0, theme)
	return out.String()
}

func formatEntryPath(path string, theme cliTheme) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return theme.text.Render(path)
	}
	return theme.accent.Render(parts[0]) +
		theme.muted.Render("/") +
		theme.text.Render(parts[1])
}

func appendTree(out *strings.Builder, node treeNode, prefix string, depth int, theme cliTheme) {
	names := make([]string, 0, len(node))
	for name := range node {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		last := i == len(names)-1
		out.WriteString(theme.muted.Render(prefix))
		if last {
			out.WriteString(theme.muted.Render("└── "))
		} else {
			out.WriteString(theme.muted.Render("├── "))
		}
		if depth == 0 {
			out.WriteString(theme.strong(theme.accent, name))
		} else {
			out.WriteString(theme.text.Render(name))
		}
		out.WriteByte('\n')
		next := prefix + "│   "
		if last {
			next = prefix + "    "
		}
		appendTree(out, node[name], next, depth+1, theme)
	}
}
