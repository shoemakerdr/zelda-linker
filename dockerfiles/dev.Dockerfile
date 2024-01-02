FROM debian

RUN apt update \
        ; \
    apt install -y \
        git \
        procps \
        neovim \
        curl \
        build-essential \
        manpages-dev \
        ;

# RUN curl -Ls https://micro.mamba.pm/api/micromamba/osx-64/latest | tar -xvj bin/micromamba \
#         ; \
#     eval "$(./bin/micromamba shell hook -s posix)" \
#         ; \
#     ./bin/micromamba shell init -s bash -p ~/micromamba \
#         ; \
#     echo "micromamba activate" >> ~/.bashrc \
#         ;


COPY elf_samples elf_samples
