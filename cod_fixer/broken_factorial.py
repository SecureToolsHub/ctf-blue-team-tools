def factorial(n):
    if n == 1:
        return 1
    return n * factorial(n - 1)


def main():
    for i in [5, 3, 1, 0]:
        print(f"{i}! = {factorial(i)}")


if __name__ == "__main__":
    main()
