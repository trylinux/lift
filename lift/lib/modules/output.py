import os
from datetime import datetime


class Output:
    def __init__(self, verbosity = 1, output_file = None):
        self.verbosity = verbosity
        self.output_file = output_file
        if self.output_file:
            self.output_file = os.path.abspath(self.output_file)
            output_file_dir = os.path.dirname(self.output_file)
            if not os.path.exists(output_file_dir):
                os.makedirs(output_file_dir)
            with open(self.output_file, "w") as f:
                f.write('')

    def write(self, text, verbosity=1):
        if verbosity < self.verbosity:
            return
        now = datetime.utcnow()
        write_format = f"{now} | {text}"
        print(write_format)
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(f"{write_format}\n")

if __name__ == '__main__':
    output = Output(verbosity=-1,output_file="/tmp/output")
    output.write("hello world")
    output.write("hello universe",verbosity=0)