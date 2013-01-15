
class UpdateDict(dict):
    """
    Use as a normal dictionary. Iterating only returns
    objects whose value have not been read before.
    """
    def __init__(self):
        self.updates = {}

    def __getitem__(self, item):
        self.updates[item] = False
        return dict.__getitem__(self, item)

    def __setitem__(self, key, value):
        if key in self:
            current_value = dict.__getitem__(self, key)
            if current_value == value:
                return
        self.updates[key] = True
        dict.__setitem__(self, key, value)

    def __iter__(self):
        for key, updated in self.updates.iteritems():
            if updated:
                yield (key, self[key])

# NOTE: Problem with the above:
#       ['a'] = 1, read, ['a'] = 2, ['a'] = 1, read
#       should check at time of read

class UpdateD(dict):
    # (sent_value, stored_value)
    def __setitem__(self, key, value):
        if key not in self:
            dict.__setitem__(self, key, (None, value))
            return
        sent_value, stored_value = dict.__getitem__(self, key)
        dict.__setitem__(self, key, (sent_value, value))

    def __getitem__(self, item):
        sent_value, stored_value = dict.__getitem__(self, item)
        dict.__setitem__(self, item, (stored_value, stored_value))
        return stored_value

    def __iter__(self):
        for key, (sent_value, stored_value) in self.iteritems():
            if sent_value != stored_value:
                dict.__setitem__(self, key, (stored_value, stored_value))
                yield (key, stored_value)

