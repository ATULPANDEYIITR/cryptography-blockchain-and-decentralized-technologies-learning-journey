# Probability basics

## Introduction

Probability is the mathematical framework used to describe uncertainty. It assigns numerical values between 0 and 1 to events, where 0 represents an impossible event and 1 represents a certain event.

Probability is used in statistics, finance, insurance, engineering, medicine, computer science, artificial intelligence, operations research, telecommunications, quality control, reliability engineering, risk management, and scientific experimentation.

The three implementations in this repository approach probability from different programming perspectives:

- Python provides a broad educational implementation with many mathematical models, simulations, statistical calculations, reliability examples, and validation routines.
- JavaScript demonstrates probability using arrays, sets, maps, classes, functional programming patterns, asynchronous execution, random simulation, and browser interaction.
- C++ develops a technical quality-control case study using classes, structures, STL containers, random-number generation, validation, statistical calculations, and an industry-style simulation model.

All three implementations use standard language facilities and do not require third-party packages.

## Fundamental terminology

### Random experiment

A random experiment is a process whose exact outcome cannot be known with certainty before it occurs.

Examples include:

- Rolling a die
- Tossing a coin
- Selecting a card
- Inspecting a manufactured component
- Measuring the lifetime of a machine
- Observing the number of network requests arriving during a time interval

The experiment must have a well-defined set of possible outcomes.

### Outcome

An outcome is one possible result of a random experiment.

For a six-sided die, the elementary outcomes are:

`1`, `2`, `3`, `4`, `5`, and `6`.

### Sample space

The sample space, usually written as `S`, is the collection of all possible outcomes.

For one fair die:

`S = {1, 2, 3, 4, 5, 6}`

The Python and JavaScript implementations explicitly construct sample spaces using tuples, sets, arrays, and other collections.

### Event

An event is a subset of the sample space.

For a die:

`E = {2, 4, 6}`

is the event that the result is even.

### Elementary event

An elementary event contains one outcome.

For example:

`{4}`

represents the event that a die produces four.

### Certain event

The entire sample space is a certain event:

`P(S) = 1`

### Impossible event

The empty set is an impossible event:

`P(∅) = 0`

## Probability axioms

Probability satisfies three fundamental properties.

### Non-negativity

For every event `A`:

`P(A) >= 0`

### Normalization

The probability of the entire sample space is:

`P(S) = 1`

### Countable additivity

For mutually exclusive events, probabilities add:

`P(A1 ∪ A2 ∪ ...) = P(A1) + P(A2) + ...`

These properties form the foundation for the probability rules implemented throughout the three programs.

## Classical probability

When elementary outcomes are equally likely:

`P(A) = number of favorable outcomes / total number of outcomes`

For a fair die, three of the six outcomes are even:

`P(even) = 3 / 6 = 0.5`

The Python implementation expresses this through `classical_probability()`. The JavaScript implementation provides `classicalProbability()`, while the C++ program implements the same principle through `classicalProbability()`.

The equal-likelihood assumption is important. The formula cannot automatically be applied to situations in which outcomes have different probabilities.

## Empirical probability

Empirical probability estimates probability from observed data:

`estimated probability = observed successes / number of trials`

For example, if a coin produces 527 heads in 1,000 trials:

`estimated P(heads) = 527 / 1000`

The estimate is not necessarily exactly equal to the theoretical probability. Random variation causes sample results to fluctuate.

The Python and JavaScript implementations demonstrate this distinction using simulation.

## Subjective probability

Subjective probability represents a degree of belief based on available information, judgment, or a probabilistic model.

Examples include:

- A forecast probability
- A risk estimate
- A probability assigned to an uncertain business event

Subjective probabilities must still obey probability rules when they are used as a coherent probability model.

## Event operations

Events can be manipulated using set operations.

### Union

`A ∪ B`

means that A or B occurs, including the possibility that both occur.

### Intersection

`A ∩ B`

means that both A and B occur.

### Complement

`Aᶜ`

means that A does not occur.

### Difference

`A - B`

means that A occurs but B does not.

Python uses native set operations to demonstrate these relationships.

## Complement rule

For any event A:

`P(Aᶜ) = 1 - P(A)`

If:

`P(A) = 0.27`

then:

`P(Aᶜ) = 0.73`

The complement rule is particularly useful when the requested event is difficult to count directly but its complement is easy to calculate.

## Addition rule

For two events:

`P(A ∪ B) = P(A) + P(B) - P(A ∩ B)`

The intersection is subtracted because it is counted twice when `P(A)` and `P(B)` are added.

If the events are mutually exclusive:

`P(A ∩ B) = 0`

and the formula becomes:

`P(A ∪ B) = P(A) + P(B)`

A common mistake is to add probabilities without checking whether the events overlap.

## Mutually exclusive events

Two events are mutually exclusive if they cannot occur together.

For a single die roll:

- `A = roll an even number`
- `B = roll an odd number`

are mutually exclusive.

They cannot both occur on the same roll.

Mutual exclusivity is different from independence.

## Independence

Events A and B are independent when the occurrence of one does not change the probability of the other.

The mathematical condition is:

`P(A ∩ B) = P(A)P(B)`

Equivalently, when the relevant conditional probability exists:

`P(A | B) = P(A)`

Independence is a modeling property. It should not be assumed merely because two events appear unrelated.

## Mutual exclusivity versus independence

These concepts should not be confused.

If two events have positive probabilities and are mutually exclusive, then:

`P(A ∩ B) = 0`

If they were also independent:

`P(A ∩ B) = P(A)P(B)`

which would be positive.

Therefore, nontrivial mutually exclusive events cannot also be independent.

The distinction is demonstrated in the Python and JavaScript probability rules.

## Conditional probability

Conditional probability describes the probability of A when B is known to have occurred:

`P(A | B) = P(A ∩ B) / P(B)`

provided:

`P(B) > 0`

The condition changes the reference population.

For example, when drawing two cards without replacement, the probability that the second card is an ace changes if the first card is already known to be an ace.

Before any information:

`P(ace) = 4 / 52`

After an ace has been removed:

`P(second card is ace | first card is ace) = 3 / 51`

The C++ and Python implementations explicitly demonstrate this distinction.

## Multiplication rule

Rearranging the conditional probability equation gives:

`P(A ∩ B) = P(A | B)P(B)`

The equivalent form is:

`P(A ∩ B) = P(B | A)P(A)`

This rule is useful for sequences of dependent events.

For a series of events:

`P(A1 ∩ A2 ∩ ... ∩ An)`

can be decomposed into a sequence of conditional probabilities.

## With replacement and without replacement

Sampling with replacement means that an item is returned after being selected.

The probability structure therefore remains unchanged from one draw to the next when the selection mechanism is uniform.

Sampling without replacement changes the population after every draw.

The JavaScript and Python programs explicitly compare these two situations.

For a population containing four different objects, two draws produce:

With replacement:

`4² = 16`

ordered outcomes.

Without replacement:

`4 × 3 = 12`

ordered outcomes.

This distinction is fundamental in card problems, quality inspection, surveys, and finite-population sampling.

## Bayes' theorem

Bayes' theorem reverses a conditional relationship:

`P(A | B) = P(B | A)P(A) / P(B)`

Using the law of total probability for the denominator:

`P(A | B) = P(B | A)P(A) / [P(B | A)P(A) + P(B | Aᶜ)P(Aᶜ)]`

Bayes' theorem is useful when the observed evidence is known but the underlying cause is uncertain.

## Diagnostic-test example

Suppose:

- Disease prevalence is 1%.
- Test sensitivity is 99%.
- False-positive probability is 5%.

Then:

`P(disease) = 0.01`

`P(positive | disease) = 0.99`

`P(positive | no disease) = 0.05`

Bayes' theorem gives the probability of disease given a positive result.

The important concept is that test accuracy alone does not determine the posterior probability. The base rate of the condition also matters.

The Python and JavaScript programs calculate this explicitly.

## Law of total probability

Suppose events `A1, A2, ..., An` form a partition of the sample space.

Then:

`P(B) = Σ P(B | Ai)P(Ai)`

This is useful when an event can arise through several mutually exclusive mechanisms.

The manufacturing example uses two machines:

- Machine A produces 70% of the products and has a 2% defect rate.
- Machine B produces 30% of the products and has an 8% defect rate.

The overall defect probability is:

`P(defect) = P(defect | A)P(A) + P(defect | B)P(B)`

The three implementations use this example in different ways.

## Counting principles

Probability often depends on counting the size of a sample space.

### Multiplication principle

If one stage has `m` choices and another has `n` choices, the combined process has:

`m × n`

possible outcomes when the choices combine independently in the counting sense.

### Factorial

For a non-negative integer `n`:

`n! = n(n-1)(n-2)...1`

and:

`0! = 1`

Factorials count arrangements of distinct objects.

### Permutations

The number of ordered selections of `r` objects from `n` distinct objects is:

`P(n,r) = n! / (n-r)!`

### Combinations

The number of unordered selections is:

`C(n,r) = n! / [r!(n-r)!]`

Python uses `math.factorial()`, `math.perm()`, and `math.comb()`. JavaScript uses `BigInt` to preserve exact integer values for larger counting operations. C++ implements integer counting with explicit overflow checks.

## Random variables

A random variable maps outcomes of a random experiment to numerical values.

A discrete random variable has countable possible values.

A continuous random variable can take values across an interval or continuous domain.

The notation `X` commonly represents a random variable.

Examples:

- `X = number of heads in 10 coin flips`
- `X = lifetime of a component`
- `X = number of requests arriving during one minute`

## Probability mass function

For a discrete random variable:

`P(X = x)`

is the probability mass function value at x.

All probability mass values must be non-negative and sum to 1.

The Python `DiscreteDistribution` class and JavaScript `DiscreteDistribution` class explicitly validate this condition.

## Cumulative distribution function

The cumulative distribution function is:

`F(x) = P(X <= x)`

A CDF is non-decreasing and approaches 0 toward the lower extreme and 1 toward the upper extreme.

For continuous variables, interval probabilities can be calculated from CDF differences:

`P(a < X <= b) = F(b) - F(a)`

## Expected value

For a discrete random variable:

`E[X] = Σ xP(X=x)`

The expected value is the probability-weighted average of possible outcomes.

For a fair six-sided die:

`E[X] = (1+2+3+4+5+6)/6 = 3.5`

The expected value does not have to be an outcome that can actually occur. A fair die cannot produce 3.5, but 3.5 is its expected value.

## Linearity of expectation

For random variables X and Y:

`E[X + Y] = E[X] + E[Y]`

This property does not require independence.

More generally:

`E[aX + b] = aE[X] + b`

Linearity of expectation is useful in combinatorial probability and expected-cost calculations.

## Variance

Variance measures the spread of a random variable around its mean:

`Var(X) = E[(X - μ)²]`

An equivalent expression is:

`Var(X) = E[X²] - E[X]²`

Variance is measured in squared units.

## Standard deviation

Standard deviation is:

`σ = sqrt(Var(X))`

It has the same units as the original variable.

The Python, JavaScript, and C++ implementations calculate variance for discrete distributions.

## Covariance

Covariance measures how two variables vary together:

`Cov(X,Y) = E[(X-μX)(Y-μY)]`

Positive covariance indicates that larger values of one variable tend to occur with larger values of the other.

Negative covariance indicates an opposite linear tendency.

Zero covariance does not generally prove independence.

## Correlation

Pearson correlation standardizes covariance:

`ρ = Cov(X,Y) / (σXσY)`

Correlation is bounded between -1 and 1.

Correlation measures linear association. It does not establish causation.

## Bernoulli distribution

A Bernoulli random variable has two outcomes, usually represented as 0 and 1.

If:

`P(X=1)=p`

then:

`P(X=0)=1-p`

The Bernoulli distribution models one binary trial.

Examples include:

- Pass/fail
- Defective/non-defective
- Click/no click
- Default/no default

The JavaScript implementation includes `bernoulliPMF()`.

## Binomial distribution

The binomial distribution counts successes in `n` independent Bernoulli trials with common success probability `p`.

Its PMF is:

`P(X=k) = C(n,k)p^k(1-p)^(n-k)`

The assumptions are important:

- Fixed number of trials
- Two possible outcomes per trial
- Constant success probability
- Appropriate independence between trials

The Python, JavaScript, and C++ programs calculate binomial probabilities.

## Geometric distribution

Using the convention implemented here, the geometric variable represents the trial number on which the first success occurs.

For `k >= 1`:

`P(X=k) = (1-p)^(k-1)p`

The geometric distribution has the memoryless property:

`P(X > m+n | X > m) = P(X > n)`

The definition of a geometric distribution varies across texts. Some define the variable as the number of failures before the first success. The convention must therefore be checked before interpreting formulas.

## Negative binomial distribution

The negative binomial distribution generalizes the geometric setting by modeling the number of trials or failures required to achieve a specified number of successes.

It is useful for repeated-event processes such as:

- Number of attempts until several successful outcomes
- Event counts in overdispersed data
- Repeated reliability or operational processes

The current implementations focus on the geometric and binomial special cases rather than duplicating a full negative-binomial implementation.

## Hypergeometric distribution

The hypergeometric distribution models sampling without replacement.

If:

- `N` = population size
- `K` = number of successes in the population
- `n` = number drawn
- `k` = number of successes observed

then:

`P(X=k) = C(K,k)C(N-K,n-k) / C(N,n)`

Unlike the binomial distribution, successive draws are generally dependent because the population changes.

The Python and JavaScript implementations provide complete hypergeometric PMFs.

## Poisson distribution

The Poisson distribution models counts of events occurring over a fixed interval under appropriate assumptions.

Its PMF is:

`P(X=k) = e^(-λ) λ^k / k!`

where `λ` is the expected number of events in the interval.

Typical modeling assumptions include:

- Events occur independently in the relevant model.
- The average rate is stable over the interval.
- Multiple events in an infinitesimally small interval are negligible under the limiting construction.

Examples include:

- Calls arriving at a service desk
- Defects occurring along a fixed production length
- Requests arriving at a server

The Python, JavaScript, and C++ implementations calculate Poisson probabilities.

## Continuous random variables

For a continuous distribution, probability is assigned to intervals rather than individual points.

For a standard continuous model:

`P(X=x) = 0`

for an exact point x.

The probability density function is not itself a probability at a point. Probabilities are obtained by integrating the density over an interval.

## Uniform distribution

A continuous uniform variable on `[a,b]` has constant density:

`f(x) = 1/(b-a)`

for `a <= x <= b`.

Its CDF between the boundaries is:

`F(x) = (x-a)/(b-a)`

The Python implementation demonstrates the PDF and CDF.

## Exponential distribution

The exponential distribution commonly models waiting time between events in a Poisson process.

For rate `λ > 0`:

`f(x) = λe^(-λx)`

for `x >= 0`.

Its CDF is:

`F(x) = 1 - e^(-λx)`

The exponential distribution is memoryless:

`P(X>s+t | X>s) = P(X>t)`

The Python and JavaScript implementations demonstrate the CDF and PDF-related calculations.

## Normal distribution

The normal distribution has density:

`f(x) = [1/(σsqrt(2π))] exp[-(x-μ)²/(2σ²)]`

The parameters are:

- `μ`: mean
- `σ`: standard deviation

The standard normal distribution has:

`μ = 0`

and:

`σ = 1`

The standardized variable is:

`Z = (X-μ)/σ`

The Python implementation uses the standard-library error function for the normal CDF. The JavaScript implementation uses a numerical approximation. C++ implements the normal PDF directly.

## The 68-95-99.7 rule

For a normally distributed variable, approximate central probabilities are:

- Within 1 standard deviation: about 68%
- Within 2 standard deviations: about 95%
- Within 3 standard deviations: about 99.7%

These percentages are properties of the normal distribution. They should not automatically be applied to arbitrary data.

## Sampling distributions

A statistic computed from a sample is itself a random variable.

Examples include:

- Sample mean
- Sample proportion
- Sample variance

The distribution of a statistic over repeated samples is called its sampling distribution.

## Law of large numbers

The law of large numbers explains why empirical averages tend to approach their theoretical expectation under appropriate conditions as the number of observations grows.

A simulation does not guarantee that every successive sample mean moves monotonically toward the theoretical value. Random fluctuations remain possible.

The Python program demonstrates this by simulating increasingly large samples of die rolls.

## Central limit theorem

The central limit theorem states, under broad regularity conditions, that suitably standardized sums or sample means approach a normal distribution as sample size increases.

For a population with mean `μ` and standard deviation `σ`, the approximate standard deviation of the sample mean is:

`σ / sqrt(n)`

This quantity is called the standard error.

The Python implementation repeatedly samples from a finite die population and measures the resulting sample means.

## Monte Carlo methods

Monte Carlo methods estimate quantities through repeated random sampling.

The Python and JavaScript implementations estimate π using random points inside a unit square.

A point `(x,y)` is inside a quarter-circle when:

`x² + y² <= 1`

The quarter-circle occupies approximately:

`π/4`

of the unit square.

Therefore:

`π ≈ 4 × inside_points / total_points`

The C++ implementation performs the same estimation using `<random>`.

Monte Carlo estimates fluctuate because they are random estimates. Increasing the number of samples generally reduces sampling error.

## Random-number generation

The three languages use different standard facilities:

- Python uses `random.Random`.
- JavaScript uses `Math.random()`.
- C++ uses `<random>`, including `std::mt19937`, uniform distributions, and discrete distributions.

Pseudo-random number generators are deterministic algorithms initialized from a seed or internal state.

A fixed seed is useful for reproducible experiments.

## Simulation is not cryptographic randomness

Ordinary simulation random-number generators are not automatically appropriate for security-sensitive operations.

Probability simulations can use ordinary pseudo-random generators when their statistical behavior is suitable.

Security-sensitive operations such as authentication tokens, password reset links, and cryptographic keys require cryptographically secure random generation.

The programs deliberately use ordinary simulation generators because their purpose is probability education and numerical experimentation.

## Reliability

A series system works only when every component works.

Under independence:

`R_series = R1R2...Rn`

A parallel system works when at least one component works.

Under independence:

`R_parallel = 1 - (1-R1)(1-R2)...(1-Rn)`

The Python, JavaScript, and C++ programs demonstrate both calculations.

These formulas depend on the independence assumption. Real systems may have common-cause failures, shared power supplies, shared networks, environmental conditions, or correlated component behavior.

## Manufacturing quality-control case study

The C++ program develops probability into a technical system rather than using only isolated formulas.

The modeled organization has two production machines.

Machine A:

- Selection probability: 70%
- Defect rate: 2%

Machine B:

- Selection probability: 30%
- Defect rate: 8%

The system answers several questions:

1. What is the theoretical overall defect probability?
2. What is the probability that a defective product originated from Machine B?
3. What defect rate appears in a simulated inspection sample?
4. How many observed defects came from each machine?

## C++ architecture

The C++ case study is divided into several components.

### Probability utility functions

Functions such as `validateProbability()`, `safeDivide()`, `conditionalProbability()`, `bayesTheorem()`, and `totalProbability()` centralize mathematical validation and reduce repeated logic.

### Machine structure

The `Machine` structure stores:

- Machine name
- Machine-selection probability
- Defect probability

This keeps related data together.

### QualityControlSystem class

`QualityControlSystem` contains the machine population and random generator.

Its responsibilities include:

- Validating machine probabilities
- Calculating theoretical defect probability
- Calculating a posterior machine probability
- Running inspection simulations

### SimulationResult structure

The simulation returns:

- Number of inspections
- Number of defects
- Defects attributed to each machine

Separating the result from the simulation process makes the system easier to inspect and test.

## Bayesian calculation in the case study

The probability that a defective product came from Machine B is:

`P(B | defect) = P(defect | B)P(B) / P(defect)`

The denominator is calculated with total probability:

`P(defect) = P(defect | A)P(A) + P(defect | B)P(B)`

Using the stated parameters:

`P(defect) = (0.02)(0.70) + (0.08)(0.30)`

which gives:

`0.038`

The posterior probability is therefore:

`P(B | defect) = (0.08)(0.30) / 0.038`

which is approximately `0.631579`.

This does not mean that every defective product has that origin. It is the model's probability for the source conditional on observing a defect.

## Exact independent portfolio model

The Python and C++ implementations also model a small portfolio of independent loss positions.

The positions are:

- Position A: 10% loss probability, loss amount 1000
- Position B: 20% loss probability, loss amount 2000
- Position C: 5% loss probability, loss amount 5000

Each position has two states:

- No loss
- Specified loss

The implementation combines these states iteratively to build an exact distribution.

For three binary positions, there are only:

`2³ = 8`

state combinations.

This approach is appropriate for small numbers of positions.

## Expected portfolio loss

For the portfolio model, the expected loss can be calculated directly:

`E[L] = Σ loss × P(loss)`

It can also be obtained from individual expected losses when linearity of expectation applies.

For the three positions:

`E[L] = (0.10)(1000) + (0.20)(2000) + (0.05)(5000)`

which equals:

`750`

The exact distribution additionally allows probabilities of specific loss thresholds to be calculated.

## Independence assumption in portfolio risk

The exact portfolio implementation assumes independent losses.

This is a major modeling assumption.

Real-world risks can be correlated. Examples include:

- Multiple suppliers affected by one disaster
- Multiple assets exposed to the same market event
- Several machines affected by the same power failure
- Several network components affected by the same infrastructure outage

If dependence exists, multiplying independent probabilities can produce an incorrect model.

## Edge cases

Probability implementations should handle invalid inputs explicitly.

Important cases include:

- Probability below 0
- Probability above 1
- Zero denominator in conditional probability
- Empty distributions
- Probabilities that do not sum to 1
- Negative sample sizes
- Number of successes larger than number of trials
- Invalid distribution parameters
- Zero standard deviation in correlation calculations
- Negative loss amounts
- Invalid reliability values
- Integer overflow in combinatorial calculations

The three programs include validation and error handling appropriate to their language.

## Continuous-probability edge case

For a continuous random variable, confusing density with probability is a common error.

For a normal distribution, the PDF value at zero is approximately:

`0.3989`

This does not mean that the probability of obtaining exactly zero is 0.3989.

The probability of an interval must be obtained by integrating the density or using CDF differences.

For a continuous distribution:

`P(X = x) = 0`

under the ordinary continuous model.

## Common probability mistakes

### Adding probabilities of overlapping events

Incorrect:

`P(A ∪ B) = P(A) + P(B)`

when A and B overlap.

Correct:

`P(A ∪ B) = P(A) + P(B) - P(A ∩ B)`

### Assuming independence

Two events being described separately does not establish independence.

Independence must follow from the underlying mechanism or a justified model assumption.

### Confusing `P(A|B)` with `P(B|A)`

These quantities generally differ.

Bayes' theorem provides the relationship between them.

### Ignoring base rates

A highly accurate test can still have a relatively low positive predictive probability when the condition being tested is rare.

### Confusing mutually exclusive events with independent events

Mutually exclusive events cannot occur together. Independent events can occur together according to the product rule.

### Treating simulation as exact

A simulation produces an estimate.

The theoretical probability and empirical probability are related but not identical.

### Treating correlation as causation

Correlation measures statistical association. It does not by itself establish a causal mechanism.

### Ignoring sampling design

With-replacement and without-replacement sampling have different probability structures.

### Using an inappropriate distribution

A binomial model requires conditions such as a fixed number of trials and an appropriate constant success probability.

A Poisson model has its own assumptions.

A normal approximation should not be applied blindly to every dataset.

## Probability distribution selection

| Situation | Common model |
|---|---|
| One binary trial | Bernoulli |
| Number of successes in fixed independent trials | Binomial |
| Trial number of first success | Geometric |
| Number of trials/failures until several successes | Negative binomial |
| Sampling without replacement | Hypergeometric |
| Count of events in a suitable fixed interval | Poisson |
| Continuous variable equally distributed across an interval | Uniform |
| Waiting time between suitable Poisson events | Exponential |
| Continuous bell-shaped model | Normal |

The distribution is selected from the structure of the random mechanism, not simply from the appearance of a dataset.

## Performance considerations

Probability problems can have very different computational costs.

### Direct enumeration

If a sample space has `n` binary choices, it can contain:

`2^n`

outcomes.

Enumeration is useful for small educational examples but becomes impractical rapidly.

### Dynamic distribution construction

The portfolio model constructs a distribution incrementally rather than manually listing every state.

For a small number of binary positions, this is easy to understand and computationally practical.

### Combinatorial arithmetic

Exact combinations can become extremely large.

Python's arbitrary-precision integers avoid ordinary fixed-width integer overflow.

JavaScript uses `BigInt` for exact combination calculations.

The C++ implementation uses `unsigned long long` and explicitly detects overflow. A production C++ implementation requiring arbitrary-size exact integers would need an arbitrary-precision integer facility.

### Numerical stability

Expressions involving very small probabilities or very large counts can underflow or overflow.

For large probability models, logarithmic calculations are often preferable.

For example, products such as:

`p1 × p2 × ... × pn`

can become numerically difficult when many probabilities are very small.

## Statistical versus computational probability

The programs combine two related approaches.

### Analytical probability

Analytical formulas calculate probabilities directly from a mathematical model.

Examples include:

- Binomial PMF
- Poisson PMF
- Bayes' theorem
- Total probability
- Reliability formulas

### Computational probability

Computational methods approximate or explore probability through computation.

Examples include:

- Monte Carlo simulation
- Random sampling
- Empirical frequency estimation
- Repeated experiments

Analytical calculations can be exact within their mathematical and numerical assumptions. Simulation provides estimates and is especially useful when exact calculation is difficult.

## Python implementation

The Python implementation is the broadest study-oriented component.

Important elements include:

- `classical_probability()`
- `empirical_probability()`
- `conditional_probability()`
- `bayes_theorem()`
- `total_probability()`
- `DiscreteDistribution`
- `binomial_pmf()`
- `geometric_pmf()`
- `poisson_pmf()`
- `hypergeometric_pmf()`
- Uniform distribution functions
- Exponential distribution functions
- Normal distribution functions
- Expected-value and variance calculations
- Covariance and correlation
- Monte Carlo π estimation
- Law of large numbers demonstration
- Central limit theorem demonstration
- Reliability calculations
- Markov-chain simulation
- Portfolio loss distribution
- Input validation
- Self-tests

Python is particularly suitable for mathematical demonstrations because numerical expressions can be written compactly and standard-library facilities provide factorials, combinations, random sampling, statistics, and special mathematical functions.

## JavaScript implementation

The JavaScript implementation emphasizes language mechanisms that are useful when probability calculations are integrated into applications.

It demonstrates:

- `Set` for sample-space operations
- `Map` for probability distributions
- Functions for probability rules
- `BigInt` for exact combinatorial values
- Classes for reusable probability models
- Array methods for functional data processing
- Random simulation
- Error handling
- Promises and asynchronous execution
- Browser DOM interaction
- A quality-control class
- Reliability calculations
- Distribution functions

JavaScript is useful when probability calculations are part of interactive web applications, dashboards, browser simulations, educational interfaces, and event-driven systems.

The browser demonstration creates a small interactive simulation when executed in a page environment.

## C++ implementation

The C++ program focuses on a realistic technical system.

It demonstrates:

- Strongly structured data models
- Classes
- Structures
- STL containers
- Random distributions
- Input validation
- Exceptions
- Exact combinatorial calculations within fixed-width limits
- Quality-control simulation
- Reliability
- Statistical calculations
- Portfolio-loss modeling
- Monte Carlo simulation
- Assertions and self-tests
- Explicit performance considerations

C++ is particularly relevant when probability calculations are embedded in high-performance systems, simulation engines, scientific applications, quantitative systems, embedded software, or other applications where memory and execution characteristics matter.

## Comparison of the three implementations

| Aspect | Python | JavaScript | C++ |
|---|---|---|---|
| Educational mathematical notation | Strong | Strong | Strong |
| Interactive browser use | Limited without additional framework | Native | Not typical |
| Standard numerical facilities | Extensive standard library | Standard APIs | Standard library |
| Arbitrary-precision integers | Built in | `BigInt` | Not built into standard integer types |
| Object-oriented modeling | Classes | Classes/prototypes | Classes and structures |
| Functional processing | Comprehensions and functions | Array methods and functions | Algorithms and callable objects |
| Asynchronous programming | Available but not central here | Central language capability | Threading and asynchronous facilities available |
| Memory control | Automatic | Automatic | Explicit low-level control available |
| Performance control | High-level | High-level | Fine-grained |
| Case-study emphasis | Broad probability laboratory | Application-oriented JavaScript | Technical system design |

## Markov processes

The Python implementation includes a finite-state Markov-chain demonstration.

A Markov process models transitions between states.

The defining property is that, within the model, the distribution of the next state depends on the current state rather than requiring the entire past.

A transition matrix contains probabilities such that each row sums to 1.

For states `Low`, `Medium`, and `High`, a row such as:

`[0.70, 0.25, 0.05]`

means that when the current state is `Low`, the next state is:

- Low with probability 0.70
- Medium with probability 0.25
- High with probability 0.05

The transition matrix must be interpreted according to the state ordering used by the model.

## Probability bounds

Sometimes the complete distribution is unknown.

Probability inequalities can still provide useful bounds.

### Markov's inequality

For a non-negative random variable X and `a > 0`:

`P(X >= a) <= E[X] / a`

The bound may be loose, but it requires only the expected value and non-negativity.

### Chebyshev's inequality

For any random variable with finite variance:

`P(|X-μ| >= k) <= σ²/k²`

Chebyshev's inequality provides a distribution-independent bound based on mean and variance.

The Python implementation demonstrates both inequalities.

## Security considerations

Probability calculations can appear in security systems, but ordinary probability simulation should not be confused with cryptographic security.

Important considerations include:

- Use cryptographically secure random generators for secrets.
- Do not use simulation randomness for authentication tokens.
- Validate externally supplied numerical inputs.
- Protect systems from denial-of-service inputs such as extremely large requested sample sizes.
- Avoid uncontrolled combinatorial enumeration.
- Consider floating-point precision when probability thresholds affect security decisions.
- Treat probabilistic results as model outputs rather than guarantees.

The implementations use standard pseudo-random generators because they are performing simulations rather than generating cryptographic secrets.

## Production considerations

A production probability system should define:

- The mathematical model
- Assumptions
- Input constraints
- Numerical precision requirements
- Random-number-generation requirements
- Reproducibility requirements
- Error-handling behavior
- Monitoring requirements
- Test coverage
- Performance limits
- Data provenance
- Model validation procedures

A numerical result is meaningful only when the model, data, and assumptions are appropriate for the intended use.

## Testing considerations

The implementations include self-tests for fundamental mathematical behavior.

Examples include:

- Fair-die probabilities
- Combination calculations
- Binomial probabilities
- Normal distribution values
- Reliability edge cases
- Invalid probability rejection
- Conditional-probability denominator validation

Tests should include both ordinary cases and boundary conditions.

Useful boundary cases include:

- Probability 0
- Probability 1
- Zero trials
- One trial
- All successes
- No successes
- Empty collections
- Invalid parameters
- Degenerate distributions

## Reproducibility

Simulation results depend on random-number-generator state.

Using a fixed seed allows the same program and algorithm to reproduce the same pseudo-random sequence.

This is useful for:

- Testing
- Debugging
- Comparing algorithm changes
- Educational demonstrations
- Controlled experiments

For production stochastic systems, reproducibility requirements should be designed explicitly rather than assumed.

## Model assumptions

Probability formulas are conditional on their assumptions.

Examples:

- Binomial models assume an appropriate repeated Bernoulli structure.
- Hypergeometric models represent finite sampling without replacement.
- Poisson models represent a suitable event-count process.
- Reliability products assume independence when components are multiplied directly.
- Bayesian calculations depend on prior probabilities and conditional likelihoods.
- Monte Carlo estimates depend on the sampling mechanism.
- Normal approximations depend on appropriate distributional conditions.

Changing an assumption can change the correct probability model.

## Practical applications

Probability concepts demonstrated in the implementations apply to:

- Quality control
- Reliability engineering
- Insurance risk
- Financial risk modeling
- Network capacity planning
- Queueing systems
- Medical testing
- Fraud detection
- Operational forecasting
- Software testing
- Security analysis
- Telecommunications
- Scientific experiments
- Inventory management
- Demand modeling
- Monte Carlo simulation
- Statistical inference

The same probability rules can support very different applications because the events and random variables change while the mathematical structure remains consistent.

## Important distinctions

### Probability versus statistics

Probability generally starts with a model and derives consequences.

Statistics generally starts with observed data and uses it to estimate parameters, test hypotheses, or construct models.

The two fields are closely related but use uncertainty in different directions.

### Theoretical probability versus empirical frequency

Theoretical probability comes from a specified mathematical model.

Empirical probability comes from observations.

Large samples can make empirical frequencies approach theoretical probabilities under appropriate conditions, but finite samples remain subject to random variation.

### Independent versus identically distributed

Independent means observations do not affect one another under the model.

Identically distributed means they follow the same probability distribution.

A collection can be independent without being identically distributed, and identically distributed variables need not be independent.

### Exact calculation versus approximation

Some probability problems have exact formulas.

Others require numerical approximation, simulation, numerical integration, or other computational methods.

The choice depends on the mathematical structure, numerical requirements, and computational resources.

## Implementation limitations

The educational implementations intentionally favor transparency over a specialized numerical-probability framework.

Important limitations include:

- Very large combinatorial values can exceed fixed-width C++ integer types.
- Some formulas use direct floating-point arithmetic and can lose numerical precision for extreme parameters.
- The JavaScript normal CDF uses an approximation rather than a specialized high-precision implementation.
- The portfolio model assumes independent binary loss events.
- The reliability formulas assume independent components.
- Simulation estimates depend on sample size and random variation.
- The examples are not designed to replace domain-specific statistical validation for production decisions.

These limitations are part of the distinction between an educational implementation and a specialized numerical or statistical production system.

## Core formulas

| Concept | Formula |
|---|---|
| Complement | `P(Aᶜ) = 1 - P(A)` |
| Union | `P(A ∪ B) = P(A) + P(B) - P(A ∩ B)` |
| Conditional probability | `P(A\|B) = P(A ∩ B) / P(B)` |
| Independence | `P(A ∩ B) = P(A)P(B)` |
| Bayes | `P(A\|B) = P(B\|A)P(A) / P(B)` |
| Total probability | `P(B) = Σ P(B\|Ai)P(Ai)` |
| Discrete expectation | `E[X] = ΣxP(X=x)` |
| Variance | `Var(X) = E[(X-μ)²]` |
| Standard deviation | `σ = sqrt(Var(X))` |
| Binomial PMF | `C(n,k)p^k(1-p)^(n-k)` |
| Poisson PMF | `e^(-λ)λ^k/k!` |
| Standardization | `Z = (X-μ)/σ` |
| Standard error of mean | `σ/sqrt(n)` |
| Series reliability | `Π Ri` |
| Parallel reliability | `1 - Π(1-Ri)` |
| Markov inequality | `P(X≥a) ≤ E[X]/a` |
| Chebyshev inequality | `P(|X-μ|≥k) ≤ σ²/k²` |

## Running the implementations

### Python

Run the Python file with a standard Python 3 installation:

`python probability_basics.py`

The program prints demonstrations, simulations, probability calculations, formulas, and self-test results.

### JavaScript

Run the JavaScript file with a modern JavaScript runtime:

`node probability_basics.js`

When executed in a browser, the file also contains a guarded DOM demonstration that creates an interactive coin-flip simulation.

### C++

Compile the C++ program using C++17 or a later standard:

`g++ -std=c++17 -O2 probability_basics.cpp -o probability_basics`

Then run the resulting executable.

The program uses the C++ standard library only.

## Relationship between the implementations

The implementations intentionally overlap on foundational concepts so that the mathematical rules can be compared across languages, while each implementation has a distinct emphasis.

Python expands the topic into a broad mathematical laboratory. It includes distributions, statistical moments, simulations, reliability, Markov processes, probability bounds, and an exact small portfolio model.

JavaScript emphasizes application-level behavior. It demonstrates probability through browser-compatible code, collections, classes, functional operations, asynchronous execution, and interactive simulation.

C++ emphasizes a structured technical case study. The quality-control system combines probability theory with object-oriented design, STL data structures, random distributions, simulation, validation, error handling, and explicit computational constraints.

Together, the implementations demonstrate that probability is not merely a collection of formulas. It is a framework for modeling uncertainty, and software makes those models executable, testable, simulatable, and applicable to real systems.
