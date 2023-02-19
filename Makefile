TARGET = ft_traceroute
CC = gcc
CFLAGS = -g -Wall -Wextra -Werror
RM = rm -rf

SRC = $(wildcard ./src/*.c)
OBJ = $(SRC:.c=.o)
INC = ./include

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -I $(INC) -o $@

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ -I $(INC)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(TARGET)

re: fclean all

.PHONY: all clean fclean re
