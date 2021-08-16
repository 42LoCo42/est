est: src/main.zig
	zig build -Drelease-fast
	cp zig-out/bin/est .
	strip est

test: est src/main.zig
	./est -g public secret
	./est -s public secret < src/main.zig > sig
	cat sig src/main.zig | ./est -v public
	tac sig src/main.zig | ./est -v public || true

clean:
	rm public secret sig
