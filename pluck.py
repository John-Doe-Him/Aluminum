class CI:
    def __init__(self, citree=None, comptree=None):
        # default list if nothing passed
        self.citree = citree if citree is not None else [50, 0, 52]
        self.comptree = comptree
        self.fab = {
            "return stmt: \\",
            "stats",
            "is fsb/FAB connection"
        }
