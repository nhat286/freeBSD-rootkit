* Checks whether:
    1. each proc in the allproc list is in the pidhashtbl
    2. each proc that exists in the pidhashtbl is in the allproc list
    3. each thread in each proc exists in the tidhashtbl
    4. nprocs is consistent with the number of elements in allproc list and pidhashtbl
    5. for each proc, actual nthreads is consistent with the p\_numthreads field of the proc.
