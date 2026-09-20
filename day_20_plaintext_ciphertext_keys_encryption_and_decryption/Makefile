install:
	python -m pip install -r requirements.txt

test:
	python -m pytest tests -v

run:
	python src/encryption_demo.py

keys:
	python src/key_demo.py

cpp:
	g++ cpp/encryption_demo.cpp -o cpp/encryption_demo.exe

cpp-run:
	cpp/encryption_demo.exe

clean:
	if exist cpp\encryption_demo.exe del cpp\encryption_demo.exe
	if exist __pycache__ rmdir /s /q __pycache__
	if exist .pytest_cache rmdir /s /q .pytest_cache