

class UpdateDict(dict):
    # (sent_value, stored_value)
    def __setitem__(self, key, value):
        if key not in self:
            dict.__setitem__(self, key, (None, value))
            return
        sent_value, stored_value = dict.__getitem__(self, key)
        dict.__setitem__(self, key, (sent_value, value))

    def __getitem__(self, item):
        sent_value, stored_value = dict.__getitem__(self, item)
        # mark read
        dict.__setitem__(self, item, (stored_value, stored_value))
        return stored_value

    def __iter__(self):
        for key, (sent_value, stored_value) in dict.iteritems(self):
            if sent_value != stored_value:
                yield key

    def iteritems(self):
        for key, (sent_value, stored_value) in dict.iteritems(self):
            if sent_value != stored_value:
                # mark read
                dict.__setitem__(self, key, (stored_value, stored_value))
                yield (key, stored_value)

    def __len__(self):
        counter = 0
        for key, (sent_value, stored_value) in dict.iteritems(self):
            if sent_value != stored_value:
                counter += 1
        return counter

