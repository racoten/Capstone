# Code
```c
% Define the variable and the function f(x) = 3tan(x)
x = linspace(-1.5, 1.5, 500);  % Create an array of x values from -1.5 to 1.5
y_true = 3 * tan(x);  % True function values

% Define the Taylor series terms
y_1 = zeros(size(x));  % 1st term: 0
y_2 = 3 * (x - 0);  % 2nd term: 3(x - 0)
y_3 = y_2;  % 3rd term: Same as 2nd term because the 3rd term is zero
y_4 = y_3 + (6 / factorial(3)) * (x - 0).^3;  % 4th term
y_5 = y_4 + (36 / factorial(4)) * (x - 0).^4;  % 5th term

% Plot the function and its Taylor series approximations
figure;
hold on;
plot(x, y_true, 'k', 'LineWidth', 2);  % Plot the true function
plot(x, y_1, '--r', 'LineWidth', 2);  % Plot the 1st term
plot(x, y_2, '--g', 'LineWidth', 2);  % Plot the 2nd term
plot(x, y_3, '--b', 'LineWidth', 2);  % Plot the 3rd term
plot(x, y_4, '--m', 'LineWidth', 2);  % Plot the 4th term
plot(x, y_5, '--c', 'LineWidth', 2);  % Plot the 5th term

% Add labels and legend
xlabel('x');
ylabel('f(x)');
title('Taylor Series Approximation of f(x) = 3tan(x)');
legend('f(x) = 3tan(x)', '1st term', '2nd term', '3rd term', '4th term', '5th term');
grid on;
hold off;
```

![[Pasted image 20230917094622.png]]