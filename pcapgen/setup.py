from distutils.core import setup, Extension
 
module1 = Extension('_pcapgen',
                    sources = ['pcapgen.cpp', 'pcapgen_wrap.cxx'],
                    extra_compile_args = ['--std=c++11'],
                    extra_link_args = ['-lnet', '-lpcap'])
  
setup (name = 'PcapGen',
       version = '1.0',
       description = 'Pcap generation',
       ext_modules = [module1],
       py_modules = ['pcapgen'])

