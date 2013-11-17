(deffacts init-data
    (cpu-utilization 99)
    (low-pri-process 3456))

(defrule stabalize-cpu
    (cpu-utilization 99)
    (low-pri-process ?pid)
    =>
    (printout t crlf "killing process " ?pid crlf)
    (assert (new-value ( killprocess ?pid )) ))
