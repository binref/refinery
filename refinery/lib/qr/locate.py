from __future__ import annotations

import math

from typing import TYPE_CHECKING, NamedTuple

from refinery.lib.qr.tables import ALIGNMENT_POSITIONS, version_size

if TYPE_CHECKING:
    from PIL.Image import Image


class FinderPattern(NamedTuple):
    x: float
    y: float
    estimated_module_size: float


class QRGrid(NamedTuple):
    modules: list[list[bool]]
    version: int
    size: int


def _binarize(image: Image) -> list[list[bool]]:
    gray = image.convert('L')
    width, height = gray.size
    pixels = list(gray.tobytes())
    block = max(width, height) // 8
    if block < 7:
        block = 7
    if block % 2 == 0:
        block += 1
    integral = [0] * ((width + 1) * (height + 1))
    stride = width + 1
    for y in range(height):
        row_sum = 0
        for x in range(width):
            row_sum += pixels[y * width + x]
            integral[(y + 1) * stride + (x + 1)] = (
                integral[y * stride + (x + 1)] + row_sum)
    half = block // 2
    matrix: list[list[bool]] = []
    for y in range(height):
        row: list[bool] = []
        y0 = max(0, y - half)
        y1 = min(height - 1, y + half)
        for x in range(width):
            x0 = max(0, x - half)
            x1 = min(width - 1, x + half)
            count = (y1 - y0 + 1) * (x1 - x0 + 1)
            total = (
                integral[(y1 + 1) * stride + (x1 + 1)]
                - integral[y0 * stride + (x1 + 1)]
                - integral[(y1 + 1) * stride + x0]
                + integral[y0 * stride + x0]
            )
            row.append(pixels[y * width + x] * count < total)
        matrix.append(row)
    return matrix


def _check_ratio(counts: list[int]) -> bool:
    total = sum(counts)
    if total < 7:
        return False
    module = total / 7.0
    tolerance = module * 0.7
    return (
        abs(counts[0] - module) < tolerance
        and abs(counts[1] - module) < tolerance
        and abs(counts[2] - 3 * module) < 3 * tolerance
        and abs(counts[3] - module) < tolerance
        and abs(counts[4] - module) < tolerance
    )


def _scan_line_for_patterns(
    line: list[bool], fixed_coord: float, is_horizontal: bool
) -> list[FinderPattern]:
    candidates: list[FinderPattern] = []
    n = len(line)
    i = 0
    while i < n:
        if not line[i]:
            i += 1
            continue
        counts = [0, 0, 0, 0, 0]
        state = 0
        while i < n:
            if line[i] == (state % 2 == 0):
                counts[state] += 1
            else:
                if state == 4:
                    if _check_ratio(counts):
                        total = sum(counts)
                        center = i - total + counts[0] + counts[1] + counts[2] // 2 + counts[2] % 2
                        module_size = total / 7.0
                        if is_horizontal:
                            candidates.append(FinderPattern(
                                center, fixed_coord, module_size))
                        else:
                            candidates.append(FinderPattern(
                                fixed_coord, center, module_size))
                    counts[0] = counts[2]
                    counts[1] = counts[3]
                    counts[2] = counts[4]
                    counts[3] = 1
                    counts[4] = 0
                    state = 3
                    i += 1
                    continue
                else:
                    state += 1
                    counts[state] = 1
            i += 1
        if state == 4 and _check_ratio(counts):
            total = sum(counts)
            center = i - total + counts[0] + counts[1] + counts[2] // 2 + counts[2] % 2
            module_size = total / 7.0
            if is_horizontal:
                candidates.append(FinderPattern(
                    center, fixed_coord, module_size))
            else:
                candidates.append(FinderPattern(
                    fixed_coord, center, module_size))
    return candidates


def _cross_check_vertical(
    matrix: list[list[bool]], cx: int, cy: int, expected_count: int,
) -> float:
    height = len(matrix)
    counts = [0, 0, 0, 0, 0]
    y = cy
    while y >= 0 and matrix[y][cx]:
        counts[2] += 1
        y -= 1
    if y < 0:
        return -1
    while y >= 0 and not matrix[y][cx]:
        counts[1] += 1
        y -= 1
    if y < 0:
        return -1
    while y >= 0 and matrix[y][cx]:
        counts[0] += 1
        y -= 1
    y = cy + 1
    while y < height and matrix[y][cx]:
        counts[2] += 1
        y += 1
    if y >= height:
        return -1
    while y < height and not matrix[y][cx]:
        counts[3] += 1
        y += 1
    if y >= height:
        return -1
    while y < height and matrix[y][cx]:
        counts[4] += 1
        y += 1
    if not _check_ratio(counts):
        return -1
    total = sum(counts)
    if abs(total - expected_count) > expected_count * 0.5:
        return -1
    return y - total + counts[0] + counts[1] + counts[2] / 2.0


def _cross_check_horizontal(
    matrix: list[list[bool]], cx: int, cy: int, expected_count: int,
) -> float:
    width = len(matrix[0])
    counts = [0, 0, 0, 0, 0]
    x = cx
    while x >= 0 and matrix[cy][x]:
        counts[2] += 1
        x -= 1
    if x < 0:
        return -1
    while x >= 0 and not matrix[cy][x]:
        counts[1] += 1
        x -= 1
    if x < 0:
        return -1
    while x >= 0 and matrix[cy][x]:
        counts[0] += 1
        x -= 1
    x = cx + 1
    while x < width and matrix[cy][x]:
        counts[2] += 1
        x += 1
    if x >= width:
        return -1
    while x < width and not matrix[cy][x]:
        counts[3] += 1
        x += 1
    if x >= width:
        return -1
    while x < width and matrix[cy][x]:
        counts[4] += 1
        x += 1
    if not _check_ratio(counts):
        return -1
    total = sum(counts)
    if abs(total - expected_count) > expected_count * 0.5:
        return -1
    return x - total + counts[0] + counts[1] + counts[2] / 2.0


def _cross_check_diagonal(
    matrix: list[list[bool]], cx: int, cy: int, expected_count: int,
) -> bool:
    height = len(matrix)
    width = len(matrix[0])
    counts = [0, 0, 0, 0, 0]
    y, x = cy, cx
    while y >= 0 and x >= 0 and matrix[y][x]:
        counts[2] += 1
        y -= 1
        x -= 1
    if y < 0 or x < 0:
        return False
    while y >= 0 and x >= 0 and not matrix[y][x]:
        counts[1] += 1
        y -= 1
        x -= 1
    if y < 0 or x < 0:
        return False
    while y >= 0 and x >= 0 and matrix[y][x]:
        counts[0] += 1
        y -= 1
        x -= 1
    y, x = cy + 1, cx + 1
    while y < height and x < width and matrix[y][x]:
        counts[2] += 1
        y += 1
        x += 1
    if y >= height or x >= width:
        return False
    while y < height and x < width and not matrix[y][x]:
        counts[3] += 1
        y += 1
        x += 1
    if y >= height or x >= width:
        return False
    while y < height and x < width and matrix[y][x]:
        counts[4] += 1
        y += 1
        x += 1
    if not _check_ratio(counts):
        return False
    total = sum(counts)
    return abs(total - expected_count) <= expected_count * 0.5


def _find_finder_patterns(matrix: list[list[bool]]) -> list[FinderPattern]:
    height = len(matrix)
    width = len(matrix[0]) if height else 0
    candidates: list[FinderPattern] = []
    for y in range(height):
        raw = _scan_line_for_patterns(matrix[y], float(y), True)
        for fp in raw:
            cx = int(fp.x + 0.5)
            cy = int(fp.y + 0.5)
            if cx < 0 or cx >= width or cy < 0 or cy >= height:
                continue
            expected = int(fp.estimated_module_size * 7 + 0.5)
            vy = _cross_check_vertical(matrix, cx, cy, expected)
            if vy < 0:
                continue
            hx = _cross_check_horizontal(
                matrix, cx, int(vy + 0.5), expected)
            if hx < 0:
                continue
            if not _cross_check_diagonal(
                matrix, int(hx + 0.5), int(vy + 0.5), expected
            ):
                continue
            candidates.append(FinderPattern(
                hx, vy, fp.estimated_module_size))
    return _cluster_candidates(candidates)


def _cluster_candidates(
    candidates: list[FinderPattern],
) -> list[FinderPattern]:
    if not candidates:
        return []
    groups: list[list[FinderPattern]] = []
    for c in candidates:
        merged = False
        for g in groups:
            rep = g[0]
            dist = math.hypot(c.x - rep.x, c.y - rep.y)
            if dist < rep.estimated_module_size * 5:
                g.append(c)
                merged = True
                break
        if not merged:
            groups.append([c])
    result: list[FinderPattern] = []
    for g in groups:
        if len(g) < 2:
            continue
        avg_x = sum(p.x for p in g) / len(g)
        avg_y = sum(p.y for p in g) / len(g)
        avg_ms = sum(p.estimated_module_size for p in g) / len(g)
        result.append(FinderPattern(avg_x, avg_y, avg_ms))
    if not result:
        for g in groups:
            avg_x = sum(p.x for p in g) / len(g)
            avg_y = sum(p.y for p in g) / len(g)
            avg_ms = sum(p.estimated_module_size for p in g) / len(g)
            result.append(FinderPattern(avg_x, avg_y, avg_ms))
    return result


def _distance(a: FinderPattern, b: FinderPattern) -> float:
    return math.hypot(a.x - b.x, a.y - b.y)


def _cross_product_sign(
    o: FinderPattern, a: FinderPattern, b: FinderPattern,
) -> float:
    return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)


def _order_finders(
    finders: list[FinderPattern],
) -> tuple[FinderPattern, FinderPattern, FinderPattern]:
    d01 = _distance(finders[0], finders[1])
    d02 = _distance(finders[0], finders[2])
    d12 = _distance(finders[1], finders[2])
    if d01 >= d02 and d01 >= d12:
        top_left = finders[2]
        a, b = finders[0], finders[1]
    elif d02 >= d01 and d02 >= d12:
        top_left = finders[1]
        a, b = finders[0], finders[2]
    else:
        top_left = finders[0]
        a, b = finders[1], finders[2]
    if _cross_product_sign(top_left, a, b) > 0:
        top_right, bottom_left = a, b
    else:
        top_right, bottom_left = b, a
    return top_left, top_right, bottom_left


def _estimate_version(
    top_left: FinderPattern,
    top_right: FinderPattern,
    bottom_left: FinderPattern,
) -> int:
    d_top = _distance(top_left, top_right)
    d_left = _distance(top_left, bottom_left)
    avg_module = (
        top_left.estimated_module_size
        + top_right.estimated_module_size
        + bottom_left.estimated_module_size
    ) / 3.0
    modules = ((d_top + d_left) / 2.0) / avg_module + 7
    version = round((modules - 17) / 4)
    return max(1, min(40, version))


def _perspective_transform(
    src: list[tuple[float, float]],
    dst: list[tuple[float, float]],
) -> list[float]:
    ax, ay = src[0]
    bx, by = src[1]
    cx, cy = src[2]
    dx, dy = src[3]
    ax2, ay2 = dst[0]
    bx2, by2 = dst[1]
    cx2, cy2 = dst[2]
    dx2, dy2 = dst[3]
    rows: list[list[float]] = [
        [ax, ay, 1, 0, 0, 0, -ax2 * ax, -ax2 * ay, ax2],
        [0, 0, 0, ax, ay, 1, -ay2 * ax, -ay2 * ay, ay2],
        [bx, by, 1, 0, 0, 0, -bx2 * bx, -bx2 * by, bx2],
        [0, 0, 0, bx, by, 1, -by2 * bx, -by2 * by, by2],
        [cx, cy, 1, 0, 0, 0, -cx2 * cx, -cx2 * cy, cx2],
        [0, 0, 0, cx, cy, 1, -cy2 * cx, -cy2 * cy, cy2],
        [dx, dy, 1, 0, 0, 0, -dx2 * dx, -dx2 * dy, dx2],
        [0, 0, 0, dx, dy, 1, -dy2 * dx, -dy2 * dy, dy2],
    ]
    for col in range(8):
        max_row = col
        for row in range(col + 1, 8):
            if abs(rows[row][col]) > abs(rows[max_row][col]):
                max_row = row
        rows[col], rows[max_row] = rows[max_row], rows[col]
        pivot = rows[col][col]
        if abs(pivot) < 1e-10:
            continue
        for j in range(col, 9):
            rows[col][j] /= pivot
        for row in range(8):
            if row == col:
                continue
            factor = rows[row][col]
            for j in range(col, 9):
                rows[row][j] -= factor * rows[col][j]
    return [rows[i][8] for i in range(8)]


def _transform_point(
    coeffs: list[float], x: float, y: float,
) -> tuple[float, float]:
    a, b, c, d, e, f, g, h = coeffs
    denom = g * x + h * y + 1.0
    if abs(denom) < 1e-10:
        denom = 1e-10
    px = (a * x + b * y + c) / denom
    py = (d * x + e * y + f) / denom
    return px, py


def _find_alignment_pattern(
    matrix: list[list[bool]],
    coeffs: list[float],
    expected_x: float,
    expected_y: float,
    module_size: float,
) -> tuple[float, float] | None:
    ix, iy = _transform_point(coeffs, expected_x, expected_y)
    ix_int = int(ix + 0.5)
    iy_int = int(iy + 0.5)
    height = len(matrix)
    width = len(matrix[0])
    search = int(module_size * 5)
    for dy in range(-search, search + 1):
        for dx in range(-search, search + 1):
            ny = iy_int + dy
            nx = ix_int + dx
            if 0 <= ny < height and 0 <= nx < width and matrix[ny][nx]:
                if _check_alignment_at(matrix, nx, ny):
                    return (float(nx), float(ny))
    return None


def _check_alignment_at(
    matrix: list[list[bool]], cx: int, cy: int,
) -> bool:
    height = len(matrix)
    width = len(matrix[0])
    for dx in range(-2, 3):
        for dy in range(-2, 3):
            nx, ny = cx + dx, cy + dy
            if nx < 0 or nx >= width or ny < 0 or ny >= height:
                return False
            is_dark = matrix[ny][nx]
            if dx == 0 and dy == 0:
                if not is_dark:
                    return False
            elif abs(dx) == 2 or abs(dy) == 2:
                if not is_dark:
                    return False
            elif abs(dx) == 1 or abs(dy) == 1:
                if is_dark:
                    return False
    return True


def _sample_grid(
    matrix: list[list[bool]],
    top_left: FinderPattern,
    top_right: FinderPattern,
    bottom_left: FinderPattern,
    version: int,
) -> QRGrid:
    size = version_size(version)
    src = [
        (top_left.x, top_left.y),
        (top_right.x, top_right.y),
        (bottom_left.x, bottom_left.y),
    ]
    dst = [
        (3.5, 3.5),
        (size - 3.5, 3.5),
        (3.5, size - 3.5),
    ]
    avg_module = (
        top_left.estimated_module_size
        + top_right.estimated_module_size
        + bottom_left.estimated_module_size
    ) / 3.0
    br_x = top_right.x + bottom_left.x - top_left.x
    br_y = top_right.y + bottom_left.y - top_left.y
    initial_src = src + [(br_x, br_y)]
    initial_dst = dst + [(size - 3.5, size - 3.5)]
    coeffs = _perspective_transform(initial_dst, initial_src)
    if version >= 2:
        positions = ALIGNMENT_POSITIONS[version]
        if len(positions) >= 2:
            ax_expected = float(positions[-1])
            ay_expected = float(positions[-1])
            found = _find_alignment_pattern(
                matrix, coeffs, ax_expected, ay_expected, avg_module)
            if found:
                br_x, br_y = found
                new_src = src + [(br_x, br_y)]
                new_dst = dst + [(ax_expected, ay_expected)]
                coeffs = _perspective_transform(new_dst, new_src)
    height = len(matrix)
    width = len(matrix[0]) if height else 0
    grid: list[list[bool]] = []
    for row in range(size):
        grid_row: list[bool] = []
        for col in range(size):
            px, py = _transform_point(coeffs, col + 0.5, row + 0.5)
            ix = int(px)
            iy = int(py)
            if 0 <= ix < width and 0 <= iy < height:
                grid_row.append(matrix[iy][ix])
            else:
                grid_row.append(False)
        grid.append(grid_row)
    return QRGrid(grid, version, size)


def locate_qr_codes(image: Image) -> list[QRGrid]:
    matrix = _binarize(image)
    finders = _find_finder_patterns(matrix)
    if len(finders) < 3:
        return []
    results: list[QRGrid] = []
    triplets = _select_triplets(finders)
    for triplet in triplets:
        top_left, top_right, bottom_left = _order_finders(triplet)
        version = _estimate_version(top_left, top_right, bottom_left)
        try:
            grid = _sample_grid(
                matrix, top_left, top_right, bottom_left, version)
            results.append(grid)
        except Exception:
            continue
    return results


def _select_triplets(
    finders: list[FinderPattern],
) -> list[list[FinderPattern]]:
    if len(finders) == 3:
        return [finders]
    scored: list[tuple[float, list[FinderPattern]]] = []
    n = len(finders)
    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                three = [finders[i], finders[j], finders[k]]
                d01 = _distance(three[0], three[1])
                d02 = _distance(three[0], three[2])
                d12 = _distance(three[1], three[2])
                sides = sorted([d01, d02, d12])
                if sides[0] < 1:
                    continue
                ratio = sides[2] / sides[0]
                if ratio > 2.0:
                    continue
                sizes = [f.estimated_module_size for f in three]
                avg_size = sum(sizes) / 3.0
                if avg_size < 0.1:
                    continue
                size_var = sum(
                    (s - avg_size) ** 2 for s in sizes) / avg_size ** 2
                angle_score = abs(ratio - math.sqrt(2))
                score = size_var * 10 + angle_score
                scored.append((score, three))
    scored.sort(key=lambda x: x[0])
    result: list[list[FinderPattern]] = []
    used: set[int] = set()
    for _, triplet in scored:
        ids = set()
        for f in triplet:
            for idx, existing in enumerate(finders):
                if f is existing:
                    ids.add(idx)
        if ids & used:
            continue
        result.append(triplet)
        used |= ids
    if not result and len(finders) >= 3:
        result.append(finders[:3])
    return result
