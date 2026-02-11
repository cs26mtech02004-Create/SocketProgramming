from cryptography.hazmat.primitives.asymmetric import dh
def genPandG():
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    with open("globalvariable.txt", "w") as f:
        f.write(f"{p}|{g}")
