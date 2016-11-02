# frigate-duplo
##I. copy from the original frigate code https://bitbucket.org/bmood/frigaterelease
##II. modify the frigate code to output the GC format that we want for the duplo 
### to run:
./frigate program -dp

for example:  ./frigate ./tests/temp.wir -dp

### output:
outputs in file program.duplo (tests/temp.wir.duplo)
### our format:

cntGate cntFunction

cntInput1 cntInput2 cntOutput

6 onegate

7 zerogate

FN 0 4 18 2 16 10->indicate for function 0, #inputwire 4, startInputWire 18, #outputwire 4, startOutwire 16, #wire 10

2 1 0 1 2 AND  -> AND(w0,w1)=w2

......

......

F 2-> indicate for function 2

....

....

F 0 -> indicate for main function

....

....

F1 -> call function F1

F2 -> call function F2

...

##III. generate the GC for the functions: 
1. matrix multiplication
2. hamming distance
3. multiplication of 2 numbers
4. AES, RSA....

###IV. Interpreter (real value test file)
 ./frigate ./tests/temp.wir -dp -dpTest realValue.txt

