def kuhn(graph, n, m):
    match = [-1] * m
    visited = [False] * n

    def dfs(v):
        if visited[v]:
            return False
        visited[v] = True
        for u in range(m):
            if graph[v][u] is not None:
                if match[u] == -1 or dfs(match[u]):
                    match[u] = v
                    return True
        return False

    for i in range(n):
        visited = [False] * n
        dfs(i)

    return match

graph = [
    [None, 2, 5, 5**0.5, 5**0.5, 4, 4, None, None],
    [2, None, 4, 4, 5, 4, 6, None, None],
    [5, 4, None, 6, 7, 7, 2, None, None],
    [5, 4, 6, None, 7, 7, 2, None, None],
    [5**0.5, 5, 7, 7, None, 6, 3, None, None],
    [5**0.5, 5, 7, 7, 6, None, 3, None, None],
    [4, 4, 2, 2, 3, 3, None, 8, 8],
    [4, 6, None, None, None, None, 8, None, 73**0.5],
    [None, None, None, None, None, None, 8, 73**0.5, None]
]

n = len(graph)
m = len(graph[0])

matching = kuhn(graph, n, m)

print("Минимальное весовое паросочетание:")
for u, v in enumerate(matching):
    if v != -1:
        print(f"{chr(ord('a') + v)} - {chr(ord('a') + u)}")