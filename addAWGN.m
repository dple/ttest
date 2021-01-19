function out_signal = addAWGN(signal, targetSNR)
sigLength = length(signal); % length
awgnNoise = randn(size(signal)); % orignal noise
pwrSig = sqrt(sum(signal.^2))/sigLength; % signal power
pwrNoise = sqrt(sum(awgnNoise.^2))/sigLength; % noise power

scaleFactor = (pwrSig/pwrNoise)/targetSNR; %find scale factor
awgnNoise = scaleFactor*awgnNoise; 
out_signal = signal + awgnNoise; % add noise
end 

function out_signal = addAWGN(signal, targetSNR)
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
