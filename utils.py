
# https://stackoverflow.com/a/52447759
def get_path(data, path, default=None):
    try:
        for item in path:
            data = data[item]
        return data
    except (KeyError, TypeError, IndexError):
        return default


def str_to_date(date_str):
    from datetime import datetime
    if date_str is None:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        return None


def remove_duplicates(lst: list):
    seen = []
    for item in lst:
        found = False
        for seen_item in seen:
            if item == seen_item:
                found = True

        if not found:
            seen.append(item)

    return seen
