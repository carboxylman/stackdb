
class Foo {
public:
    enum Bar {
	FooBarOne = 1,
	FooBarTwo = 2,
    };

    int setFbe(enum Bar be);
    virtual int getFbe(void);

protected:
    enum Bar fbe;
};
