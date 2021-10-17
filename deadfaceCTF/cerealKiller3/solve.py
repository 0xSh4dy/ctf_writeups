import angr
import logging
target = angr.Project('./cerealKiller3',main_opts={'base_addr':0x10000})
logging.getLogger('angr').setLevel(logging.CRITICAL) #To remove the unwanted logs on the terminal
entry_state = target.factory.entry_state()
simulation = target.factory.simulation_manager(entry_state)
simulation.explore(find=0x000115b1,avoid=0x000115c4)
solution = simulation.found[0].posix.dumps(0)
print(solution)
