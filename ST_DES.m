%Input: Key64, Master Key; nt,Number of traces

%% MAIN FUNCTION

function[]=ST_DES(Key64,nt)
% COMPUTING KEY SCHEDULE

K=KeySchedule(hex2bin(Key64));

for k=1:nt
% RANDOMISING PLAINTEXT

%Generate Random Plaintext
M64 = sprintf( '%08x', uint32(rand(1,ceil(16/8)) * 2^32));

% HEADER

%Initialising header template
header=zeros(0,160); 
header(1)=[65]; %number of traces per file
header(2)=[4]; %length of expected data
header(6)=[1];
header(10)=[66]; %number of samples 
header(11)=[4]; %length of expected data
header(19)=[67]; %sample coding 
header(20)=[4]; %length of expected data
header(24)=[1];
header(28)=[81]; %plaintext
header(29)=[8]; %length of expected data
header(41)=[82]; %master key
header(42)=[8]; %length of expected data
header(54)=[83]; %ciphertext
header(55)=[8]; %length of expected data
header(67)=[95]; %end
header(68)=[0]; %end

%inputing Plaintext and Master Key into header
for i=1:8
header(32+i)=hex2dec(M64(2*i-1:2*i));
header(45+i)=hex2dec(Key64(2*i-1:2*i));
end

% HAMMING WEIGHTS

%Initialising Hamming Weight Vector
Trace=zeros(1,960+16);

% HammingWeight(M) function
% input: M s.t M is a binary vector
% output: a vector listing hamming weights for each byte of input

% DES Encrypt with HW calculations

%hex2bin
M64=hex2bin(M64);


% --- HW ---
Trace(1:8)=HW8bit(M64);
% --- -- ---

%Initial permutation of 64-bit plaintext
M=IPmatrix(M64);

% --- HW ---
Trace(9:16)=HW8bit(M);
% --- -- ---

%Initialising L and R
L=M(1:32);
R=M(33:64);

% --- HW ---
Trace(17:24) = HW4bit(L);
Trace(8+17:8+24) = HW4bit(R);
% --- -- ---    

%Expansion Permutation
Z=Ematrix(R);

% --- HW ---
Trace(16+17:16+24) = HW6bit(Z);
% --- -- ---   
    
%Use of Round Key
Y=bitxor(Z,K(1,:));

% --- HW ---
Trace(24+17:24+24) = HW6bit(Y);
% --- -- ---   

%S-boxes
X=S_box((reshape(Y,6,8))');

% --- HW ---
Trace(32+17:32+24) = HW4bit(X);
% --- -- ---   

%Permutation
W=Pmatrix(X);

% --- HW ---
Trace(40+17:40+24) = HW4bit(W);
% --- -- ---   

V=bitxor(W,L);

% --- HW ---
Trace(48+17:48+24) = HW4bit(V);
% --- -- ---   

%Initialising P-1(L) and P-1(R) 
InvPR=PmatrixInv(R);
InvPL=PmatrixInv(L);
    
% --- HW ---
Trace(56+17:56+24) = HW4bit(InvPR);   
Trace(64+17:64+24) = HW4bit(InvPL); 
% --- -- ---      
    
%Permutation
InvV=bitxor(X,InvPL);      
 
% --- HW ---
Trace(72+17:72+24) = HW4bit(InvV);
% --- -- ---     

% --- HD ---
Trace(80+17:80+24) = HW4bit(bitxor(InvPR,InvV));
Trace(88+17:88+24) = HW4bit(bitxor(InvPR,InvPL));
% --- -- ---     

%E(Ri) (special version for Simulation Traces)
for ee=1:8
    ER2(8*ee-7:8*ee)=ER2matrix_(V,ee);
end
    
%---HammingWeight---
Trace(96+17:96+24) = HW8bit(ER2);  
% --- -- ---  

L=R;
R=V;
  
for j=1:15
    
    % --- HW ---
    Trace(56*j-56+121:56*j-56+128) = HW4bit(L);
    Trace(8+56*j-56+121:8+56*j-56+128) = HW4bit(R);
    % --- -- --- 
    
    %Expansion Permutation
    Z=Ematrix(R);
 
    % --- HW ---
    Trace(16+56*j-56+121:16+56*j-56+128) = HW6bit(Z);
    % --- -- --- 
    
    %Use of Round Key
    Y=bitxor(Z,K(j+1,:));
    
    % --- HW ---
    Trace(24+56*j-56+121:24+56*j-56+128) = HW6bit(Y);
    % --- -- ---     
    
    %S-boxes
    X=S_box((reshape(Y,6,8))');

    % --- HW ---
    Trace(32+56*j-56+121:32+56*j-56+128) = HW4bit(X);
    % --- -- ---     
    
    %Permutation
    W=Pmatrix(X);
    
    % --- HW ---
    Trace(40+56*j-56+121:40+56*j-56+128) = HW4bit(W);
    % --- -- ---     
    
    V=bitxor(W,L);
    
    % --- HW ---
    Trace(48+56*j-56+121:48+56*j-56+128) = HW4bit(V);
    % --- -- ---     
    
    L=R;
    R=V;
    
end

%D is the ciphertext
D=InvIPmatrix([R,L]);

% --- HW/HD ---
Trace(960+1:960+8) = HW8bit(D);
Trace(960+9:960+16) = HW8bit(bitxor(D,[R,L]));
% --- ----- ---

%bin2hex
C64=bin2hex(D);

% HEADER COMPLETION

% number of samples(length of trace/number of points) 
c=dec2hex((length(Trace)));
l=length(c);
g='00000000';
h='00000000';
for i=1:l
    g(l+1-i)=c(i);
end
for i=1:4
    h(2*i-1)=g(2*i);
    h(2*i)=g(2*i-1);
end
for i=1:4
   header(14+i)=hex2dec(h(2*i-1:2*i)); 
end

%inputing ciphertext into header
for i=1:8
header(58+i)=hex2dec(C64(2*i-1:2*i));
end

% Writing Header and Trace Vector to a file  

        FileName = sprintf('DES_Simulation_Trace_%d.otr',k);
        FID = fopen(FileName,'w');
        fwrite(FID,header,'uchar');
        fwrite(FID,Trace,'uchar');
        fclose(FID);
        fclose('all');
end
end



%% LOCAL FUNCTIONS

function[x]=bin2hex(A)
x='0000000000000000';
for i=1:16
  x(i)=dec2hex(bin2dec(num2str(A(4*i-3:4*i)))); 
end
end

function[x]=hex2bin(c)
d=length(c);
x=zeros(1,d*4);
for i=1:d
    a = str2mat(dec2bin(hex2dec(c(i)),4));
    for j=1:4
    if (a(j)=='1')
        x(j+4*i-4)=1;
    else
        x(j+4*i-4)=0;
    end
    end
end
end

function[X]= circularleftshift(Y,z) 
X=(reshape(circshift(reshape(Y,1,28)',-z),28,1))';
end

function[Y]=Ematrix(B)
E= [32	1	2	3	4	5   4	5	6	7	8	9   8	9	10	11	12	13  12	13	14	15	16	17  16	17	18	19	20	21  20	21	22	23	24	25  24	25	26	27	28	29  28	29	30	31	32	1];
for i=1:48
    Y(i)=B(E(i));
end
end

function[Y]= InvIPmatrix(B)
InvIP= [40	8	48	16	56	24	64	32  39	7	47	15	55	23	63	31  38	6	46	14	54	22	62	30  37	5	45	13	53	21	61	29  36	4	44	12	52	20	60	28  35	3	43	11	51	19	59	27  34	2	42	10	50	18	58	26  33	1	41	9	49	17	57	25];
for i=1:64
    Y(i)=B(InvIP(i));
end
end

function[Y]=IPmatrix(B)
IP=[58	50	42	34	26	18	10	2   60	52	44	36	28	20	12	4   62	54	46	38	30	22	14	6   64	56	48	40	32	24	16	8   57	49	41	33	25	17	9	1   59	51	43	35	27	19	11	3   61	53	45	37	29	21	13	5   63	55	47	39	31	23	15	7];
for i=1:64
    Y(i)=B(IP(i));
end
end

function [K] =KeySchedule(key64)

% Define shift values
v=[1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1];

% T<-PC1(key64) s.t T=(c,d) (initial values)
[c,d]=PC1matrix(key64);

%Defining K matrix

for i=1:16
    c=circularleftshift(c,v(i));
    d=circularleftshift(d,v(i));
    K(i,:)=PC2matrix(c,d);
end

end

function [Z,X]=PC1matrix(B)

PC1L= [57	49	41	33	25	17	9   1	58	50	42	34	26	18  10	2	59	51	43	35	27  19	11	3	60	52	44	36];

PC1R= [63	55	47	39	31	23	15  7	62	54	46	38	30	22  14	6	61	53	45	37	29  21	13	5	28	20	12	4];

for i=1:28
    Z(i)=B(PC1L(i));
    X(i)=B(PC1R(i));
end

end

function[Y]=PC2matrix(X,Z)
B=[X,Z];
PC2= [14	17	11	24	1	5	3	28  15	6	21	10	23	19	12	4   26	8	16	7	27	20	13	2   41	52	31	37	47	55	30	40  51	45	33	48	44	49	39	56  34	53	46	42	50	36	29	32];
for i=1:48
    Y(i)=B(PC2(i));
end
end

function[Y]=Pmatrix(B)
P= [16  7   20  21  29  12  28  17  1   15  23  26  5   18  31  10  2   8   24  14  32  27  3   9   19  13  30  6   22  11  4   25];
for i=1:32
    Y(i)=B(P(i));
end
end

function[B]=S_box(A)

%each rows defines 1 S-box i.e row 1 defines S1, row 2 defines S2,etc
S= [14	4	13	1	2	15	11	8	3	10	6	12	5	9	0	7   0	15	7	4	14	2	13	1	10	6	12	11	9	5	3	8   4	1	14	8	13	6	2	11	15	12	9	7	3	10	5	0   15	12	8	2	4	9	1	7	5	11	3	14	10	0	6	13
15	1	8	14	6	11	3	4	9	7	2	13	12	0	5	10  3	13	4	7	15	2	8	14	12	0	1	10	6	9	11	5   0	14	7	11	10	4	13	1	5	8	12	6	9	3	2	15  13	8	10	1	3	15	4	2	11	6	7	12	0	5	14	9
10	0	9	14	6	3	15	5	1	13	12	7	11	4	2	8   13	7	0	9	3	4	6	10	2	8	5	14	12	11	15	1   13	6	4	9	8	15	3	0	11	1	2	12	5	10	14	7   1   10	13	0	6	9	8	7	4	15	14	3	11	5	2	12
7	13	14	3	0	6	9	10	1	2	8	5	11	12	4	15  13	8	11	5	6	15	0	3	4	7	2	12	1	10	14	9   10	6	9	0	12	11	7	13	15	1	3	14	5	2	8	4   3	15	0	6	10	1	13	8	9	4	5	11	12	7	2	14
2	12	4	1	7	10	11	6	8	5	3	15	13	0	14	9   14	11	2	12	4	7	13	1	5	0	15	10	3	9	8	6   4	2	1	11	10	13	7	8	15	9	12	5	6	3	0	14  11	8	12	7	1	14	2	13	6	15	0	9	10	4	5	3
12	1	10	15	9	2	6	8	0	13	3	4	14	7	5	11  10	15	4	2	7	12	9	5	6	1	13	14	0	11	3	8   9	14	15	5	2	8	12	3	7	0	4	10	1	13	11	6   4	3	2	12	9	5	15	10	11	14	1	7	6	0	8	13
4	11	2	14	15	0	8	13	3	12	9	7	5	10	6	1   13	0	11	7	4	9	1	10	14	3	5	12	2	15	8	6   1	4	11	13	12	3	7	14	10	15	6	8	0	5	9	2   6	11	13	8	1	4	10	7	9	5	0	15	14	2	3	12
13	2	8	4	6	15	11	1	10	9	3	14	5	0	12	7   1	15	13	8	10	3	7	4	12	5	6	11	0	14	9	2   7	11	4	1	9	12	14	2	0	6	10	13	15	3	5	8   2	1	14	7	4	10	8	13	15	12	9	0	3	5	6	11];

B=zeros(1,32);
%Implementing the Sboxes

for k=1:8
X = A(k,:);
w = dec2bin(S(k,(bin2dec(num2str(X([1,6])))*16+bin2dec(num2str(X([2,3,4,5])))+1)),4);
for i=1:4
B(i+4*k-4) = w(i)-48;
end
end

end

function[X]= circularleftshift8(Y,z) 
X=(reshape(circshift(reshape(Y,1,8)',-z),8,1))';
end

function[c] = ER2matrix_(data,numSB)

A=zeros(1,8);
A(5:8)=data(4*numSB-3:4*numSB);

% SB 1
if (numSB==1)
    c=xor(and(A,[0 0 0 0 1 1 0 0]),circularleftshift8(A,4));
end
% SB 2
if (numSB==2)
    c=xor(and(A,[0 0 0 0 1 1 0 0]),circularleftshift8(A,4));
end
% SB 3
if (numSB==3)
    c=xor(and(A,[0 0 0 0 1 1 0 0]),circularleftshift8(A,4));
end
% SB 4 
if (numSB==4)
    c=xor(and(A,[0 0 0 0 0 1 0 1]),circularleftshift8(A,4));
end
% SB 5
if (numSB==5)
    c=xor(and(A,[0 0 0 0 1 0 1 0]),circularleftshift8(A,4));
end
% SB 6
if (numSB==6)
    c=xor(and(A,[0 0 0 0 1 1 0 0]),circularleftshift8(A,4));
end
% SB 7
if (numSB==7)
    c=xor(and(A,[0 0 0 0 1 1 0 0]),circularleftshift8(A,4));
end
% SB 8
if (numSB==8)
    c=xor(and(A,[0 0 0 0 1 0 0 1]),circularleftshift8(A,4));
end

end

function[Y]=PmatrixInv(B)
P= [16  7   20  21  29  12  28  17  1   15  23  26  5   18  31  10  2   8   24  14  32  27  3   9   19  13  30  6   22  11  4   25];
for i=1:32
    b=0;
    for j=1:32
        if (i==P(j))
            b=j;
        end
    end
    Y(i)=B(b);
end
end

function[L]=HW4bit(M)
for k=1:(length(M)/4)
    J=0;
for i=1:4
    if (M(i+k*4-4)==1)
       J=J+1;
    end  
end
L(k)=J;
end
end

function[L]=HW6bit(M)
for k=1:(length(M)/6)
    J=0;
for i=1:6
    if (M(i+k*6-6)==1)
       J=J+1;
    end  
end
L(k)=J;
end
end

function[L]=HW8bit(M)
for k=1:(length(M)/8)
    J=0;
for i=1:8
    if (M(i+k*8-8)==1)
       J=J+1;
    end  
end
L(k)=J;
end
end
