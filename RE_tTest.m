% Given two sets of data whose cardinalities are nbTraces1 and nbTraces2
% Test null hypothesis for these two datasets

% Main function
function[] = RE_tTest()

    RootFolder = 'C:\Users\51377\RnD\MAC_traces\test5'; 
    
    FixedFolder = [RootFolder, '\dataset0'];    % Fixed key and data
    RandFolder = [RootFolder, '\dataset1'];     % Fixed key and random data    

    headerLength = 108;

    FixedFilesList = ls(strcat(FixedFolder,'\*.otr'));
    RandFilesList = ls(strcat(RandFolder,'\*.otr'));

    nbTraces1 = size(FixedFilesList, 1);

    nbTraces2 = size(RandFilesList, 1);

    % Initializing trace matric
    traceCnt = 1;    
    Source = [RandFolder,'\MAC_Simulated_Trace_1.otr'];
    fid = fopen(Source, 'r');
    header = fread(fid, headerLength, 'uchar');
    data = fread(fid,'uchar');
    l = length(data); %1044; % length of trace including header
    Trace1 = zeros(nbTraces1, l);
    Trace2 = zeros(nbTraces2, l);

    % Extracting data from traces
    for traceCnt = 1 : nbTraces1
        Source = [FixedFolder,'\',FixedFilesList(traceCnt,:)];
        fid = fopen(Source, 'r');
        fread(fid, headerLength, 'uchar');
        data = fread(fid,'uchar');
        Trace1(traceCnt,1:l) = reshape(data,1,l);
        fclose(fid);
    end
    
    traceCnt = 1;
    Source = [RandFolder,'\',RandFilesList(traceCnt,:)];
    fid = fopen(Source, 'r');
    fread(fid, headerLength, 'uchar');
    data = fread(fid,'uchar');
    Trace2(traceCnt,1:l) = reshape(data,1,l);        
    fclose(fid);
        
    for traceCnt = 2 : nbTraces2
        Source = [RandFolder,'\',RandFilesList(traceCnt,:)];
        fid = fopen(Source, 'r');
        fread(fid, headerLength, 'uchar');
        data = fread(fid,'uchar');
        Trace2(traceCnt,1:l) = reshape(data,1,l);        
        fclose(fid);
    end 
    
    % Compute t-Test 
    T = Welch_tTest(Trace1(:,:), Trace2(:,:));
    
    % Change header values
    header(24)=[20];
    
    % Writing Header and Trace Vector to a file      
    FileName = [RootFolder, '\RE_tTest_MAC_Results.otr'];
    fid = fopen(FileName,'w');
    fwrite(fid,header,'uchar');
    fwrite(fid, T , 'float');
    fclose(fid);
    fclose('all');
    
end 




% Local function

% Return the mean of the dataset X 
function [M] = l_mean(X)
    card = size(X);
    nbRow = card(1);
    M = sum(X)/nbRow;
end 

% Return the variance of the dataset X
function [Var] = l_variance(X)
    card = size(X);
    nbRow = card(1);
    M = sum(X)/nbRow;
    M2 = M.^2;
    X2 = sum(X.^2)/nbRow;
    Var = X2 - M2;    
end

% Return the standard deviation of the dataset X
function [SD] = l_stddeviation(X)
    card = size(X);
    nbRow = card(1);
    M = sum(X)/nbRow;
    M2 = M.^2;
    X2 = sum(X.^2)/nbRow;
    SD = sqrt(X2 - M2);    
end

function[V] = Welch_tTest(X, Y)
    
    cardX = size(X); nbRowX = cardX(1); nbColX = cardX(2);
    cardY = size(Y); nbRowY = cardY(1); nbColY = cardY(2);
    meanX = sum(X)/nbRowX;
    varX = sum(X.^2)/nbRowX - meanX.^2;
    meanY = sum(Y)/nbRowY;
    varY = sum(Y.^2)/nbRowY - meanY.^2;
    
    V = abs((meanX - meanY)./(sqrt(varX/nbRowX + varY/nbRowY) + 0.001));
end
