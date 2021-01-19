%Input: @nt: Number of traces

%% MAIN FUNCTION

function[]=ST_MAC_addGN(startFolder, nbFolders, nbTraces0)
        
    % Root Folder
    SourceRoot = 'C:\Users\51377\RnD\DES_traces\test1\dataset';
    ResultRoot = 'C:\Users\51377\RnD\DES_traces\test6'; 
    headerLength = 68;
    
    startFile = 1;
    %TraceGen(RootFolder, 0, a, b, noise, nt1);      % Fixed key, random data
    %TraceGen(RootFolder, 1, a, b, noise, nt2);      % Fixed key, fixed data
    %TraceGen(RootFolder, 2, a, b, noise, nt3);      % Random key, random data
        
    for folderCnt = startFolder : startFolder + nbFolders - 1
        %%%Create the corresponding Result folder if it doesn't exists
        if(~exist( [ResultRoot,'\dataset', int2str(folderCnt)], 'dir'))
            mkdir(ResultRoot, strcat('\dataset',int2str(folderCnt)));
        end

        %Initialize the Source folders
        SourceFolder   = [SourceRoot, int2str(folderCnt)];
        ResultFolder = [ResultRoot, '\dataset', int2str(folderCnt)];

        SourceFilesList = ls(strcat(SourceFolder,'\*.otr'));

        if(nbTraces0 == 0)
            nbTraces = size(SourceFilesList,1);
        else
            nbTraces = nbTraces0;
        end

        for traceCnt = startFile : startFile + nbTraces -1
            Source   = [SourceFolder, '\', SourceFilesList(traceCnt,:)];
            Result = [ResultFolder, '\', SourceFilesList(traceCnt,:)];
            
            if(~isempty(Source)) 
                fid = fopen(Source,'r');

                if(fid > 0)

                    header = fread(fid, headerLength, 'uchar');
                    data = fread(fid, inf, 'uchar');
                    
                    try
                        
                        data = addGN(data, 0.1);
                                                
                        %%Save the simulated trace in a file                        
                        fic = fopen(Result, 'w');
                        count = fwrite(fic, header, 'uchar');
                        count = fwrite(fic, data, 'float');%, 'int')
                        filestatus = fclose(fic);
                        fclose('all');
                                                
                    catch e
                        disp(strcat('Error Caught: ',SourceFilesList(traceCnt,:)));
                        disp(strcat('Error line: ', int2str(e.stack.line)));
                        disp(e.message);
                        disp(' ');
                    end %end try/catch

                end %end if(fid > 0)

            end%end if isEmpty(Source)

        end 

    end 
    RE_tTest();
end

% Local function
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