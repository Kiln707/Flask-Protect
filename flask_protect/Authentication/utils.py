#
#   TimeDelta utils
#
def get_within_delta(time):
    if isinstance(time, datetime.timedelta):
        return time.seconds + time.days * 24 * 3600
    elif str(time):
        values = time.split()
        td = timedelta(**{values[1]: int(values[0])})
        return td.seconds + td.days * 24 * 3600
    raise TypeError()
