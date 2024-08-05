# koppeling-p
Adaptive DLL hijacking / dynamic export forwarding - EAT preserve

# Overview

This project is a limited, Python-only extension to the amazing project by Nick Landers (@monoxgas), available [here](https://github.com/monoxgas/Koppeling). 

# Differences

The only difference to the original project is that koppeling-p (p stands for preserve), aims to preserve the DLL target export address table during cloning. 

# Motivations

This little tool was the base for a more advanced library (Interleaver), instrumental for the [DriverJack](https://github.com/klezVirus/DriverJack) research and other ongoing projects.
