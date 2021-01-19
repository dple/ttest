%MAC algo 3
%Input plaintext of any length in hex, and two 64-bit Key's in Hex
%Output MAC
%(must include ' on either end of hex being put into the function)

function [MAC] = MACAlgo3(nt1, nt2) %(M,K1,K2)

    RootFolder = '../MAC_traces/test';    
    
    K1 = 'ABCDEF1234567890';
    K2 = '1234567890ABCDEF';
    M = '00000000000000000000000008400000000000084007123100112233440000000000000000000000';
        
    % Simulate MAC Algo3 with unsecure DES
    %TraceGen(RootFolder, 1, nt2, M, K1, K2, 0);      % Fixed p1, random p2
    %TraceGen(RootFolder, 0, nt1, M, K1, K2, 0);      % Fixed data
        
    % Simulate MAC Algo3 with secure DES
    TraceGen(RootFolder2, 1, nt2, M, K1, K2, 1);      % Fixed p1, random p2
    TraceGen(RootFolder2, 0, nt1, M, K1, K2, 1);      % Fixed data
    RE_tTest();
end 

%% LOCAL FUNCTIONS

% Generate a simulated traces
% @mode:    0 - trace with fixed p1, random p2
%           1 - fixed data
% @nt:  number of traces generated
% ResultRoot:   folder to save traces

function[] = TraceGen(ResultRoot, mode, nt, M40, Key1, Key2, secureDES)
    
    %interpreting plaintext
    h = size(M40);
    h = h(2);
    g = h*4;
    M = hex2bin_(M40, g, h);
    a = size(M);
    b = a(2);
    B = b;
    c = 0;
      
    if (mode == 0)  %         fixed data
        ResultFolder = [ResultRoot, '\dataset0']; % test1 without noise. W = HW(Data)
    else  % random p2        
        ResultFolder = [ResultRoot, '\dataset1'];   
    end 
    
    %%%Create the corresponding Result1 folder if it doesn't exists
    if(~exist(ResultFolder, 'dir'))
        mkdir(ResultFolder);
    end   
    
    %Check Size if length of messege is multiple of 64
    for i = 1 : 64
        if (rem(b, 64)~=0)
            %length of the padded message
            b = b + 1;
            %the number of zeros need to be added
            c = c + 1;
        end
    end

    %initialising padded messege PM
    PM = zeros(1, b);

    for i = 1 : B
        PM(i) = M(i);
    end

    %PM;
    %The number of 64 bit blocks
    d = b/64;
   
    %interpreting Key Inputs
    K1 = hex2bin(Key1);
    K2 = hex2bin(Key2);

        
    for k = 1 : nt               
        
        if (mode == 1)  %Generate 64-bits Random Plaintext P2            
            P2 = sprintf( '%08x', uint32(rand(1,ceil(16/8)) * 2^32));            
            for i = 1 : 16
                M40(16 + i) = P2(i);
            end 
            P2 = hex2bin(P2);
            for i = 1 : 64
                PM(64 + i) = P2(i);
            end 
            
        end 
        
        %Initialising header template
        header = zeros(0, 216); 
        header(1) = [65]; %number of traces per file
        header(2) = [4]; %length of expected data
        header(6) = [1];
        header(10) = [66]; %number of samples 
        header(11) = [4]; %length of expected data
        header(19) = [67]; %sample coding 
        header(20) = [4]; %length of expected data
        header(24) = [1]; % sampling code
        header(28) = [81]; %plaintext
        header(29) = [40]; %length of 5 block of expected data
        header(73) = [82]; % 16 bytes of master key 
        header(74) = [16]; %length of expected data
        header(94) = [83]; %ciphertext
        header(95) = [8]; %length of expected data
        header(107) = [95]; %end
        header(108) = [0]; %end
        
        %inputing Plaintext and Master Key into header
        
        for i = 1 : 40            
            header(32 + i) = hex2dec(M40(2*i - 1 : 2*i));            
        end
        for i = 1 : 8
            header(77 + i) = hex2dec(Key1(2*i - 1 : 2*i));
        end 
        for i = 1 : 8
            header(85 + i) = hex2dec(Key2(2*i - 1 : 2*i));
        end 
        
        
        %Initialising Hamming Weight Vector
        Trace = zeros(1, 5*(960 + 8 + 16) + 2*(960 + 8));     % 8 bytes XOR and 16 bytes HW/HD ciphertext
   
        
        % Initial Transformation and iterations
        C = zeros(1, 64);
        
        for i = 1 : d            
            pos = 984*(i - 1);
            % HW of input data
            Trace(pos + 1 : pos + 8) = HW8bit(hex2bin(M40(16*i - 15 : 16*i)));
            % XOR  Ciphertext ^ Plaintext
            Z = bitxor(C, PM(64*i - 63 : 64*i));
            % --- HW of C^P ---
            Trace(pos + 9 : pos + 16) = HW8bit(Z);            
            [C, patternDES] = DESencrypt(Z, K1, secureDES); %, Trace, pos + 8);
            Trace(pos + 17: pos + 984) = patternDES;
        end
        pos = pos + 984;
        %Applying K2
        [C, patternDES] = DESdecrypt(C, K2, secureDES);
        Trace(pos + 1: pos + 968) = patternDES;
        
        %Applying K3
        pos = pos + 968;
        [C, patternDES] = DESencrypt(C, K1, secureDES);
        Trace(pos + 1: pos + 968) = patternDES;
        
        %MAC
        MAC = bin2hex(C);        

        % HEADER COMPLETION

        % number of samples(length of trace/number of points) 
        c = dec2hex((length(Trace)));
        l = length(c);
        g = '00000000';
        h = '00000000';
        for i = 1 : l
            g(l + 1 - i) = c(i);
        end
        for i = 1 : 4
            h(2*i - 1) = g(2*i);
            h(2*i) = g(2*i - 1);
        end
        for i = 1 : 4
           header(14 + i) = hex2dec(h(2*i - 1 : 2*i)); 
        end

        %inputing ciphertext into header
        for i = 1 : 8
            header(98 + i) = hex2dec(MAC(2*i - 1 : 2*i));
        end
        
        % Writing Header and Trace Vector to a file  
        FileName = sprintf('MAC_Simulated_Trace_%d.otr', k);
        File = [ResultFolder, '\', FileName];
        fid = fopen(File,'w');
        fwrite(fid, header, 'uchar');
        fwrite(fid, Trace, 'uchar');
        fclose(fid);
        
    end % end of for
end % end of function



%% LOCAL FUNCTIONS

% Add white Gausian noise to the signal

function out_signal = addGN(signal, targetSNR)
    sigLength = length(signal); % length
    awgnNoise = randn(size(signal)); % orignal noise
    pwrSig = sqrt(sum(signal.^2))/sigLength; % signal power
    pwrNoise = sqrt(sum(awgnNoise.^2))/sigLength; % noise power
    
    if targetSNR ~= 0
       scaleFactor = (pwrSig/pwrNoise)/targetSNR; %find scale factor
       awgnNoise = scaleFactor*awgnNoise; 
       out_signal = signal + awgnNoise; % add noise
    else
       out_signal = awgnNoise; % noise only
    end
    
end 

function[D, patternDES] = DESencrypt(M64,Key64, secure)

%Define Key Schedule
K=KeySchedule(Key64);

%Initial permutation of 64-bit plaintext
M=IPmatrix(M64);

% --- HW ---
patternDES(1 : 8) = HW8bit(M); %(t + 9 : t + 16) = HW8bit(M);
% --- -- ---


%Initialising L and R
L=M(1:32);
R=M(33:64);

% --- HW ---
patternDES(9: 16) = HW4bit(L);
patternDES(17 : 24) = HW4bit(R);
% --- -- ---    

%Expansion Permutation
Z = Ematrix(R);

% --- HW ---
patternDES(8 + 17 : 8 + 24) = HW6bit(Z);
% --- -- ---   
    
%Use of Round Key
Y=bitxor(Z, K(1,:));

% --- HW ---
patternDES(16 + 17 : 16 + 24) = HW6bit(Y);
% --- -- ---   

%S-boxes
X=S_box((reshape(Y,6,8))');

% --- HW ---
patternDES(24 + 17 : 24 + 24) = HW4bit(X);
% --- -- ---   

%Permutation
W=Pmatrix(X);

% --- HW ---
patternDES(32 + 17 : 32 + 24) = HW4bit(W);
% --- -- ---   

V = bitxor(W,L);

% --- HW ---
patternDES(40 + 17 : 40 + 24) = HW4bit(V);
% --- -- ---   

%Initialising P-1(L) and P-1(R) 
InvPR = PmatrixInv(R);
InvPL = PmatrixInv(L);
    
% --- HW ---
patternDES(48 + 17 : 48 + 24) = HW4bit(InvPR);   
patternDES(56 + 17 : 56 + 24) = HW4bit(InvPL); 
% --- -- ---      
    
%Permutation
InvV = bitxor(X, InvPL);      
 
% --- HW ---
patternDES(64 + 17 : 64 + 24) = HW4bit(InvV);
% --- -- ---     

% --- HD ---
patternDES(72 + 17 : 72 + 24) = HW4bit(bitxor(InvPR,InvV));
patternDES(80 + 17 : 80 + 24) = HW4bit(bitxor(InvPR,InvPL));
% --- -- ---     

%E(Ri) (special version for Simulation Traces)
for ee = 1 : 8
    ER2(8*ee - 7 : 8*ee) = ER2matrix_(V, ee);
end
    
%---HammingWeight---
patternDES(88 + 17 : 88 + 24) = HW8bit(ER2);  
% --- -- ---  

L = R;
R = V;


for j = 1 : 15
    % --- HW ---
    patternDES(56*j - 56 + 121 - 8 : 56*j - 56 + 128 - 8) = HW4bit(L);
    patternDES(56*j - 56 + 121 : 56*j-56+128) = HW4bit(R);
    % --- -- --- 
    
    %Expansion Permutation
    Z = Ematrix(R);
    % --- HW ---
    patternDES(8 + 56*j-56+121 : 8 + 56*j-56+128) = HW6bit(Z);
    % --- -- --- 
    
    %Use of Round Key
    Y = bitxor(Z,K(j,:));
    patternDES(16 + 56*j-56+121 : 16 + 56*j-56+128) = HW6bit(Y);
    
    %S-boxes
    X = S_box((reshape(Y,6,8))');
    patternDES(24 + 56*j-56+121: 24 + 56*j-56+128) = HW4bit(X);
    
    %Permutation
    W = Pmatrix(X);
    patternDES(32 + 56*j-56+121 : 32 + 56*j-56+128) = HW4bit(W);
    
    V = bitxor(W,L);
    patternDES(40 + 56*j-56+121 : 40 + 56*j-56+128) = HW4bit(V);
    
    L = R;
    R = V;
end

%D is the ciphertext
D = InvIPmatrix([R,L]);
% --- HW/HD ---
patternDES(952 + 1: 952 + 8) = HW8bit(D);
patternDES(960 + 1: 960 + 8) = HW8bit(bitxor(D,[R,L]));

if (secure == 1)
    patternDES = addGN(patternDES, 0.1);
end 

end

function[D, patternDES] = DESdecrypt(C64,Key64, secure)

%Define Key Schedule
K = KeySchedule(Key64);

%Initial permutation of 64-bit plaintext
M = IPmatrix(C64);
patternDES(1: 8) = HW8bit(M);

%Initialising L and R
L = M(1:32);
R = M(33:64);% --- HW ---
patternDES(9: 16) = HW4bit(L);
patternDES(17 : 24) = HW4bit(R);

%Expansion Permutation
Z = Ematrix(R);
patternDES(8 + 17 : 8 + 24) = HW6bit(Z);
    
%Use of Round Key
Y = bitxor(Z, K(16,:));
patternDES(16 + 17 : 16 + 24) = HW6bit(Y);

%S-boxes
X = S_box((reshape(Y,6,8))');
patternDES(24 + 17 : 24 + 24) = HW4bit(X);

%Permutation
W = Pmatrix(X);
patternDES(32 + 17 : 32 + 24) = HW4bit(W);

V = bitxor(W,L);
patternDES(40 + 17 : 40 + 24) = HW4bit(V);

%Initialising P-1(L) and P-1(R) 
InvPR = PmatrixInv(R);
InvPL = PmatrixInv(L);
    
% --- HW ---
patternDES(48 + 17 : 48 + 24) = HW4bit(InvPR);   
patternDES(56 + 17 : 56 + 24) = HW4bit(InvPL); 
% --- -- ---      
    
%Permutation
InvV = bitxor(X, InvPL);      
 
% --- HW ---
patternDES(64 + 17 : 64 + 24) = HW4bit(InvV);
% --- -- ---     

% --- HD ---
patternDES(72 + 17 : 72 + 24) = HW4bit(bitxor(InvPR,InvV));
patternDES(80 + 17 : 80 + 24) = HW4bit(bitxor(InvPR,InvPL));
% --- -- ---     

%E(Ri) (special version for Simulation Traces)
for ee = 1 : 8
    ER2(8*ee - 7 : 8*ee) = ER2matrix_(V, ee);
end
    
%---HammingWeight---
patternDES(88 + 17 : 88 + 24) = HW8bit(ER2);  
% --- -- ---  

L = R;
R = V;

for j = 15:-1:1  
    patternDES(56*j - 56 + 121 - 8 : 56*j - 56 + 128 - 8) = HW4bit(L);
    patternDES(56*j - 56 + 121 : 56*j-56+128) = HW4bit(R);
    
    %Expansion Permutation
    Z = Ematrix(R);
    patternDES(8 + 56*j-56+121 : 8 + 56*j-56+128) = HW6bit(Z);
    
    %Use of Round Key
    Y=bitxor(Z,K(j,:));
    patternDES(16 + 56*j-56+121 : 16 + 56*j-56+128) = HW6bit(Y);
    
    %S-boxes
    X=S_box((reshape(Y,6,8))');
    patternDES(24 + 56*j-56+121: 24 + 56*j-56+128) = HW4bit(X);
    
    %Permutation
    W = Pmatrix(X);
    patternDES(32 + 56*j-56+121 : 32 + 56*j-56+128) = HW4bit(W);
    
    V = bitxor(W,L);
    patternDES(40 + 56*j-56+121 : 40 + 56*j-56+128) = HW4bit(V);
    
    L = R;
    R = V;
end

%D is the ciphertext
D = InvIPmatrix([R,L]);
patternDES(952 + 1: 952 + 8) = HW8bit(D);
patternDES(960 + 1: 960 + 8) = HW8bit(bitxor(D,[R,L]));

if (secure == 1)
    patternDES = addGN(patternDES, 0.1);
end 


end

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
    X = (reshape(circshift(reshape(Y,1,8)',-z),8,1))';
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
