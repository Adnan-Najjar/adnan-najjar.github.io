---
title: "Scientific Computing Notes"
date: 2024-10-12
draft: false
ShowToc: true
---
# Root Finding

## Fixed-Point Iteration
* Concept of a fixed point (g(x) = x).
* Iterative method: x<sub>n+1</sub> = g(x<sub>n</sub>).
* Convergence condition: |g'(x)| < 1.

## Newton-Raphson Method
* Iterative method based on tangent lines.
* Formula: x<sub>n+1</sub> = x<sub>n</sub> - f(x<sub>n</sub>)/f'(x<sub>n</sub>).
* Convergence and limitations.

## Secant Method
* Iterative method approximating the derivative.
* Formula: x<sub>n+1</sub> = x<sub>n</sub> - f(x<sub>n</sub>)(x<sub>n</sub> - x<sub>n-1</sub>)/(f(x<sub>n</sub>) - f(x<sub>n-1</sub>)).
* Advantages and disadvantages compared to Newton-Raphson.

## Bisection Method
* Bracketing method requiring an initial interval [a, b] where f(a)f(b) < 0.
* Iterative halving of the interval until desired accuracy is achieved.
* Convergence is guaranteed but slow.

---
# Solving Systems of Equations

## Gaussian Elimination
* Row reduction to echelon form.
* Forward elimination and back substitution.
* Number of solutions (unique, infinite, none).
* Applications in various fields.
* MATLAB code:
```matlab
A = input("Enter coeffient matric: ");
B = input("Enter source vector: ");
N = length(B);
X = zeros(N,1);
aug = [A B]
for x = 1:N-1
	for y = xeLil
		m = aug(y,x)/aug(x,x);
		aug(y,:) = aug(y,:) - m * avg(x,:);
	end
end

X(N) = aug(N, N+1)/ aug(N,N);
for p = N-1:-1:1
	X(p) = (aug(p,N+1) - aug(p,p+1:N)*X(p+1:N)) / aug(p,p);
end
```

## LU Factorization
* Decomposition of a matrix A into L (lower triangular) and U (upper triangular) matrices (A = LU).
* Solving systems of equations using forward and back substitution with L and U.
* MATLAB code:
```matlab
A = [1,2,3;4,5,6;7,8,9];
B = [6;8;9];

[L,U] = lu(A)
Y = inv(L)*B;
X = inv(U)*Y;
disp(X);
```

## Cholesky Factorization
* Decomposition of a symmetric positive definite matrix A into L (lower triangular) and its transpose L<sup>T</sup> (A = LL<sup>T</sup>).
* Solving systems of equations using forward and back substitution.
* MATLAB code:
```matlab
A = [1,2,3;4,5,6;7,8,9];
LT = chol(A);
L = transpose(LT)
```

---
# Numerical Integration

## Midpoint Rule
* Approximating integrals using rectangles.
* MATLAB code:
```matlab
f(x) = input("enter function: ");
range = input("Enter the range: ");

n = input("Enter the number of rectangles: ")

X = (range(end)-range(1))/(n);
interval = range(1):x:range(end);

midpoint = (interval(1:end-1) + interval(2:end)) / 2;

for i = 1:length(midpoint)
	sum = sum + double(f(midpoint(i)));
end

disp("The area is: " + x * sum );
```

## Trapezoidal Rule
* Approximating integrals using trapezoids.

* MATLAB code:
```matlab
syms x
f_given = input("Is f(x) given? (y/n): ", 's');

if strcmpi(f_given, 'y')
	f(x) = input("Enter function: ");
	range = input("Enter the range: ");
	n = input("Enter the number of segments: ");

	x = (range(end) - range(1)) / (n);
	interval = range(1):x:range(end);
	sum = double(f(range(1))) + double(f(range(end)));
	
	for i = 2:(length(interval)-1)
		sum = sum + 2 * double(f(interval(i)));
	end
	
	disp("The area using the Trapezoid Method is: " + round((x/2) * sum));
	
	else
		f = input("Enter all values of array f(x): ");
		lower_bound = input("Enter the lower bound of the range: ");
		upper_bound = input("Enter the upper bound of the range: ");
		n = input("Enter the number of segments: ");

		x = (upper_bound - lower_bound) / n;
		sum = double(f(1)) + double(f(end));

		for k = 2:(length(f)-1)
			sum = sum + 2 * double(f(k));
		end
	
	disp("Area using Trapezoid Method without equation is: " + (x/2) * sum);
end

%% Easy version
f = input("Enter function: ");
range = input("Enter the range: ");
n = input("Enter the number of rectangles: ");

dx = (range(end) - range(1)) / n;
x_values = range(1):dx:range(end);
y_values = subs(f, x, x_values);

integral = trapz(double(x_values), double(y_values));
```

## Simpson's Rule
* Approximating integrals using parabolas.
* MATLAB code:
```matlab
f = @(x) x.*3;
a=2;
b = 10;

n=4;
h=(b-a)/n;
x = a:h:b;

integral = (h / 3) * (f(x(1)) + 4*sum(f(x(2:2:end-1))) + 2*sum(f(x(3:2:end-2))) + f(x(end)));

disp(integral);
```

---
# Least-Squares Curve Fitting

## Linear Least Squares Regression
* Fitting a straight line to data.
* a1 = m = ()
* a0 = ^y - a1 \^x
* Coefficient of determination (R<sup>2</sup>) and standard error of the estimate.
* Interpretation of R<sup>2</sup> and correlation coefficient (r).
* MATLAB implementation using `polyfit` and `polyval`.
* Error analysis (total standard deviation, standard error).

## Linearization of Nonlinear Relationships
* Transforming nonlinear equations into linear forms (exponential, power).
* Applying linear regression to the transformed data.
* Back-transformation to obtain the nonlinear model.

---
# Numerical Solution of Ordinary Differential Equations (ODEs)

## Euler's Method
* MATLAB code:
```matlab
dydx = @(x, y) x *y;
x0 = 0;
y0 = 1;

h = 0.1;

x = x0:h:y0;
y = zeros(size(x));

y(1) = y0;

for i = 1:length(x)-1
	y(i*1) = y(i) + h * dydx(x(1), y(i));
end

%% Easy version
[x, y] = ode45(myODE, interval, y0);
```