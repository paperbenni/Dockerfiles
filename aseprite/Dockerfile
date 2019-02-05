FROM paperbenni/arch
USER root
RUN pacman -S --noconfirm ninja cmake
USER user
WORKDIR /home/user
RUN git clone https://aur.archlinux.org/aseprite-git.git
RUN makepkg