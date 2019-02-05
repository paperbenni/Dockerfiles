FROM paperbenni/arch

RUN useradd -ms /bin/bash user && usermod -aG wheel user
RUN echo "user:user" | chpasswd
RUN echo 'user ALL=(ALL:ALL) ALL' >> /etc/sudoers
RUN pacman -S --noconfirm libx11 libxcursor
WORKDIR /home/user
USER user

RUN git clone https://aur.archlinux.org/yay.git
WORKDIR /home/user/yay
RUN makepkg && mv *.pkg.tar.xz /home/user && rm -r /home/user/yay
USER root
WORKDIR /home/user
RUN pacman -U --noconfirm *.pkg.tar.xz
USER user
RUN yay --version
