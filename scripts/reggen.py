import os
from tinygrad.runtime.ops_amd import AMDIP

def gen(ip:AMDIP):
  path = os.path.join(os.path.dirname(__file__), f"../data/regs/{ip.name}_{'_'.join(map(str, ip.version))}.txt")
  with open(path, 'w+') as fd:
    fd.write('\n'.join(f'{reg.name} reg:{reg.addr:#x}' for reg in ip.regs.values()))

if __name__ == '__main__':
  # cat /sys/class/drm/card1/device/ip_discovery/die/0/<IP>/0/{major,minor,revision,base_addr}
  gen(AMDIP('gc', (9, 4, 3), (0x00002000, 0x0D800800, 0x0D800800)))
  gen(AMDIP('nbio', (7, 9, 0), (0x00000000, 0x00000D20, 0x00010400, 0x0241B000, 0x04040000, 0x00500000, 0x0241B000, 0x02420000, 0x04040000)))
