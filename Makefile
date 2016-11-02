
#COMPILERCCP = types.cpp error.cpp ast.cpp
COMPILERO = parse_driver.o scanner.o parser.o types.o error.o ast.o defines.o includes.o exprtest.o circuito.o wire.o variable.o wirepool.o typegenerate.o interpreter.o
OP =  -std=c++11 -g -O3      
GPP = g++

all: $(COMPILERO)
	$(GPP)  $(OP) -o frigate main.cpp $(COMPILERO)
#	make interp
	./frigate ./tests/validationtest.wir -i -i_validation -nowarn    
#	./battleship ./tests/validationtest.wir -i_validation
#	./frigate ~/Desktop/temp.wir
#	./frigate ./tests/temp.wir -i -sco -tiny    

interp: $(COMPILERO)
	$(GPP)  $(OP) -o battleship interpretermain.cpp $(COMPILERO)

circuits: all
	./frigate ./tests/validationtest.wir -i -i_output validationoutput.gate -nowarn
	./frigate ./tests/rsa64.wir -i -i_output rsa64.gate -nowarn
	./frigate ./tests/matrixmult16x16.wir -i -i_output matrixmult16x16.gate -nowarn
	./frigate ./tests/matrixmult8x8.wir -i -i_output matrixmult8x8.gate -nowarn
	./frigate ./tests/matrixmult5x5.wir -i -i_output matrixmult5x5.gate -nowarn
	./frigate ./tests/matrixmult3x3.wir -i -i_output matrixmult3x3.gate -nowarn
	./frigate ./tests/mult256.wir -i -i_output mult256.gate -nowarn
	./frigate ./tests/mult1024.wir -i -i_output mult1024.gate -nowarn

wirepool.o: wirepool.h wirepool.cpp wire.o
	$(GPP)  $(OP) -c -o wirepool.o wirepool.cpp

parse_driver.o: parse_driver.cc parser.o ast.h
	$(GPP)  $(OP) -c -o parse_driver.o parse_driver.cc

scanner.o: scanner.cc parser.o ast.h
	$(GPP)  $(OP) -c -o scanner.o scanner.cc -Wno-deprecated

parser.o: parser.yy scanner.h scanner.ll ast.h types.h error.h
	flex --yylineno scanner.ll 
	mv lex.Example.cc scanner.cc
	bison parser.yy -o  parser.cc
	$(GPP)  $(OP) -c -o parser.o parser.cc 

types.o: types.cpp types.h error.o variable.h
	$(GPP)  $(OP) -c -o types.o types.cpp	

error.o: error.cpp error.h
	$(GPP)  $(OP) -c -o error.o error.cpp
	
ast.o: ast.cpp ast.h types.o error.o
	$(GPP)  $(OP) -c -o ast.o ast.cpp

includes.o: includes.cpp ast.o
	$(GPP)  $(OP) -c -o includes.o includes.cpp

defines.o: defines.h defines.cpp ast.o traverse.h
	$(GPP)  $(OP) -c -o defines.o defines.cpp

exprtest.o: exprtest.cpp exprtest.hh parse_driver.o ast.h
	$(GPP)  $(OP) -c -o exprtest.o exprtest.cpp

circuito.o: circuitoutput.h circuitoutput.cpp ast.o types.o types.o wire.o wirepool.o 
	$(GPP)  $(OP) -c -o circuito.o circuitoutput.cpp

wire.o: wire.h wire.cpp
	$(GPP)  $(OP) -c -o wire.o wire.cpp

typegenerate.o: typegenerate.h typegenerate.cpp ast.h
	$(GPP)  $(OP) -c -o typegenerate.o typegenerate.cpp

variable.o: variable.h variable.cpp types.o wire.o 
	$(GPP)  $(OP) -c -o variable.o variable.cpp

interpreter.o: interpreter.h interpreter.cpp
	$(GPP)  $(OP) -c -o interpreter.o interpreter.cpp

clean:
	rm *.o
	rm stack.hh
	rm location.hh
	rm position.hh
	rm frigate
	rm scanner.cc
	rm parser.hh
	rm parser.cc
