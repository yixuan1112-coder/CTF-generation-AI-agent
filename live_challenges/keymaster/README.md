# Keymaster (live TCP)

`nc HOST PORT`. The device prints its factory provisioning log — many
(device_id, serial) pairs — then a target device_id, and grants one attempt to
authenticate its serial. Wrong serials get a flat ACCESS DENIED with no feedback,
so you cannot guess: the serial is a fixed function of the id, and you must recover
that function from the log and apply it to the target.
