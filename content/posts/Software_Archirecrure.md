---
title: "Software Architecture Notes"
date: 2024-07-12
draft: false
ShowToc: true
---
[Software Architecture Course Materials](https://my.cud.ac.ae/course/view.php?id=17512)
# Approaches to system development
## The Systems Development Life Cycle (SDLC)
---
1. Predictive Approach
	- Waterfall model
	- Planned in advance 
	- Understood and/or low technical risk requirements
2. Adaptive Approach
	- Iterative model
	- Flexible and adapt to the change
	- Uncertain and/or high technical risk requirements
### Adaptive Concepts
---
1. Incremental Development
	- completes portions of the system in increments
	- partially deployed
	- Gets part of working system into users’ hands sooner
2. Walking Skeleton
	- complete system structure is built early
	- bare-bones functionality
## The Support Phase of the SDLC
---
in Predictive it is a ==project phase==
In Adaptive it is ==separate project==
1. Maintaining the system
	-  Fix errors
	- Make adjustments
	- Update for changes
2. Enhancing the system
	- Add functionality
	- Change functionality
3. Supporting the users
	- Ongoing user training
	- Help desk
## Methodologies, Models, Tools and Techniques
---
1. Methodology
	- includes a collection of techniques, modeling and tools
2. Models
	- Abstraction
	- Understanding complex concepts by focusing on relevant parts
	- Each model shows different aspect
	- Crucial for communicating
3. Tools
	- Software applications that assists developers
4. Techniques
	- A collection of guidelines
### Approaches to Software Construction and Modeling
---
1. Structured Approach
	- collection of processes
	- Structured analysis, design and programming
2. Object-Oriented Approach
	- collection of objects
	- OO Analysis (defining classes)
	- OO Design (defining types of objects and how they interact)
	- OO Programming (duh!!)
## Agile Development
---
1. Agile Manifesto (values)
	- ==Responding to change== over following a plan.
	- ==Individuals and Interactions== over processes and tools.
	- ==Working software== over comprehensive documentation.
	- ==Customer collaboration== over contract negotiation.
2. Agile Umbrella
	- Scrum
	- Kanban
### Scrum
---
1. Split time into short fixed-length sprints (2-4 weeks)
2. Optimize the release plan and update priorities with the customer
3. Optimize the process by having retrospective after each iteration

# Diagrams
## Use Case Diagrams

* **Purpose:**  Visually represent user interactions with the system (what the system does, not how).  Understandable by both technical and non-technical stakeholders.
* **Key Elements:** Actors (users or external systems), Use Cases (specific ways of using the system), System boundary.
* **Relationships:**
    * Actor-Use Case:  Shows an actor's interaction with a use case.
    * Use Case-Use Case:  `<<include>>` (one use case calls another reusable one), `<<extend>>` (one use case is a special case of another).
* **Development Process:** Identify actors, define their goals (use cases), describe the basic flow and alternative scenarios for each use case.

## Activity Diagrams

* **Purpose:** Model workflows – sequences of activities to complete a business transaction.  Shows the flow of activities and decision points.
* **Key Elements:** Activities (represented by rounded rectangles), decision points (diamonds), concurrent paths (split and merge synchronization bars).
* **Development Process:** Identify agents (swimlanes), define activities, connect them with arrows to show the workflow.

## System Sequence Diagrams (SSDs)

* **Purpose:** Show the interaction between an actor and the system as a whole (a single object representing the entire system).  Focuses on message passing.
* **Key Elements:** Actor, :System, lifelines, messages (with parameters and return values), loops (*), optional/alternative paths ([ ]).
* **Development Process:** Identify input messages from the actor, describe messages using verb-noun naming, identify conditions (loops, optionals), and describe output return values.

## Domain Model Class Diagrams

* **Purpose:**  Model the objects and their relationships within the problem domain (without implementation details).
* **Key Elements:** Classes (with attributes), associations (with multiplicity).
* **Notation:** Class names capitalized, attribute names camelCase.

## State Machine Diagrams

* **Purpose:** Model the life cycle of an object, showing its states and transitions between them.
* **Key Elements:** States (conditions), transitions (movement between states), action expressions (activities performed during transitions), guard conditions (true/false tests for transitions), pseudo-states (start/end points), composite states (states containing other states), concurrent paths.
* **Development Process:** Identify states, transitions, and associated elements, considering exception conditions and concurrent paths.

# Functional and Non-Functional

==Software Requirements Specification (SRS)== is part of the Requirement Engineering phase, and it is a detailed document that describes both
- ==Functional==: what the system should do.
- ==Non-functional==: how the system should perform "quality attributes".
- System architecture: High-level system design.
NFRs examples:-
1. Performance
2. Availability
3. Accuracy
4. Portability
5. Scalability
6. Reuse-ability
7. Maintainability
8. Interoperability
9. Capacity
10. Manageability

# Architectural Design
## Architectural Styles

### 1. Repository Style

* **Description:**  A central data structure (the repository) is shared by independent components. Components interact with the repository to read and modify data.  Suitable for applications needing a central body of information manipulated in various ways.

* **Components:** Central data structure, independent components operating on the data structure.
* **Connectors:** Procedure calls or direct memory access.
* **Examples:** Information systems, programming environments, graphical editors, AI knowledge bases, reverse engineering systems.

* **Advantages:** Efficient data storage, centralized management (backup, security, concurrency control), shared data model.
* **Disadvantages:** Requires a priori agreement on data model, difficult to distribute data, expensive data evolution.


### 2. Pipe and Filter Style

* **Description:** Components (filters) process data streams, passing output to the input of the next filter. Suitable for applications requiring a series of independent computations on data.

* **Components:** Filters (perform local transformations).
* **Connectors:** Pipes (transmit data streams).
* **Examples:** Unix shell scripts, traditional compilers (lexical analysis, parsing, etc.).

* **Advantages:** Easy to understand overall behavior, supports reuse, easy maintenance and enhancement, supports concurrency, allows specialized analysis (throughput, deadlock).
* **Disadvantages:** Not suitable for interactive systems, excessive parsing/unparsing can lead to performance loss and increased complexity.


### 3. Object-Oriented Style

* **Description:** Components (objects) encapsulate data and operations.  Objects interact through method invocations.  Suitable for applications where data protection and related bodies of information are central.

* **Components:** Objects.
* **Connectors:** Function and procedure invocations (methods).
* **Examples:**  Many modern applications.

* **Advantages:** Data hiding allows implementation changes without affecting clients, supports design as collections of autonomous agents.
* **Disadvantages:** Objects must know each other's identity, changing object identity requires modification of all invoking objects, side effects can be problematic.


### 4. Layered Style

* **Description:** Components are organized into layers, each providing services to the layer above and acting as a client to the layer below.  Suitable for applications with distinct classes of services organized hierarchically.

* **Components:** Collections of procedures.
* **Connectors:** Procedure calls with restricted visibility.
* **Examples:** Layered communication protocols (ISO/OSI), operating systems (Unix).

* **Advantages:** Increased abstraction, changes affect at most two layers, supports reuse of layer implementations.
* **Disadvantages:** Not all systems are easily layered, performance requirements may force coupling of layers.


### 5. Interpreter Style

* **Description:** A component (interpreter) executes a program by interpreting instructions. Suitable when the appropriate language or machine for execution isn't directly available.

* **Components:** Execution engine state machine, program memory, program state memory.
* **Connectors:** Procedure calls, direct memory access.
* **Examples:** Programming language compilers (Java, Smalltalk), rule-based systems (Prolog), scripting languages (Awk, Perl).

* **Advantages:** Simulates non-implemented hardware, facilitates portability.
* **Disadvantages:** Extra indirection slows execution (though JIT compilers mitigate this).


### 6. Process-Control Style

* **Description:** Maintains specified properties of process outputs at given reference values.  Uses feedback loops to adjust process variables.

* **Components:** Process definition, control algorithm.
* **Connectors:** Data flow relations (controlled, input, manipulated variables), set points, sensors.
* **Examples:** Real-time systems (anti-lock brakes, nuclear power plants, cruise control).


### 7. Client-Server Style

* **Description:** Components are clients requesting services from servers.  Suitable for distributed data and processing.

* **Components:** Servers (provide services), clients (request services).
* **Connectors:** Network.
* **Examples:** File servers, database servers, object servers.

* **Advantages:** Straightforward data distribution, location transparency, heterogeneous platform support, easy to add/upgrade servers.
* **Disadvantages:** Performance depends on network, complex design and implementation, service discovery can be challenging.


### 8. Implicit Invocation Style

* **Description:** Components communicate through events.  A component announces an event, and other interested components respond.  Suitable for loosely-coupled, reconfigurable systems.

* **Components:** Event announcers, event listeners.
* **Connectors:** Event broadcasting system.
* **Examples:** Programming environments (debugger-editor interaction), database triggers, user interfaces.

* **Advantages:** Strong reuse support, eases system evolution.
* **Disadvantages:** Announcers lack control over responses, order and timing of responses are unpredictable.


### 9. Peer-to-Peer (P2P) Style

* **Description:** Each node (peer) acts as both client and server, sharing resources directly without relying on a central server.

* **Examples:** File-sharing applications (BitTorrent), blockchain networks.


### 10. Monolithic Architecture

* **Description:** The entire application is developed and deployed as a single unit.

* **Examples:** Traditional enterprise applications, legacy systems.


### 11. Distributed Architecture

* **Description:** System components are distributed across multiple networked locations.

* **Examples:** Microservices, cloud computing, blockchain, content delivery networks (CDNs).  This is a broad category encompassing many of the styles above.


### 12. Model-View-Controller (MVC) Architecture

* **Description:** Separates data (model), user interface (view), and user input handling (controller).

This summary provides a high-level overview.  Each style has nuances and variations depending on the specific application and implementation.

# Prototyping and User Interface (UI)

## Hi-Fi (High Fidelity)
 As close as possible to the end product.
## Lo-Fi (Low Fidelity)
Very simplified and intended only for the evaluation of design alternatives.
Use:
1. Paper, pencil, glue, transparencies...
2. Define the scenario.
Pros
1. Very inexpensive in time and money.
2. Rapid evaluation.
3. Easily changed.

## CRC Cards
---
-  Class, Responsability, Cooperations
- identify classes of a system in a light way (paper / pencil)
- Responsibility-centered design rather than properties or methods
![[Pasted image 20241206163551.png]]
## Architecture of an application
---
Class stereotypes BCE: indeicate the function of a class.---
- Boundary
	- UI of the app.
- Controller
	- control execution of actions of the app.
- Entity
	- data managed by the system.
![[Pasted image 20241206163535.png]]
# Design Patterns
## What is a Design Pattern?
- Is a common solution to a recurring problem in design.
- Abstracts a recurring design structure
- It has 4 parts:
	1. Name
	2. Problem
	3. Solution
	4. Consequences
- Language and implementation independent
- Micro-architecture
- Has existing methodologies (UML)
---
Pattern VS Design
- Pattern provide a shared language for design
- Pattern captures design expertise
- Patterns make design concepts explicit
- Pattern can capture OO design principles within a specific domain
---
Why Design Pattern?
- Designing OO software is hard so we reuse already made designs
## Design patterns Types
### 1. Creational Patterns (Object Creation)
---
#### 1. Singleton
- only one object per class
```java
public class ClassicSingleton {
    private static ClassicSingleton instance = null;
    private static Object syncObject; // to synchronize a block
    protected ClassicSingleton() {/*exists only to defeat instantiation*/ };
    public static ClassicSingleton getInstance() {
        synchronized(syncObject) {
            if (instance == null) instance = new ClassicSingleton();}
        return instance;}
}
```
#### 2. Typesafe Enum
- fixed number of objects for each class
#### 3. Abstract Factory
- Interfaces
```java
class GardenMaker {
    //Abstract Factory which returns one of three gardens
    private Garden gd;
    public Garden getGarden(String gtype) {
        gd = new VegieGarden(); //default
        if(gtype.equals("Perennial"))
            gd = new PerennialGarden();
        if(gtype.equals("Annual"))
            gd = new AnnualGarden();
        return gd;
    }
}
```
### 2. Structural Patterns (Composition)
---
#### 1. Adapter
- lets classes work together
```java
public class RoundToSquarePegAdapter extends SquarePeg {
    private RoundPeg roundPeg;
    public RoundToSquarePegAdapter(RoundPeg peg) {
        this.roundPeg = peg;}
    public void insert(String str) {
        roundPeg.insertIntoHole(str);}
}
```
#### 2. Proxy
- Control access to an object
#### 3. Decorators
- Add responsibilities dynamically
### 3. Behavioral Patterns (Interaction)
---
#### 1. Template
- Skeleton of an algorithm
#### 2. State
- Change depending on state
#### 3. Observer
- One-to-many dependency to update automatically

```java
class DigitalClockView implements Observer {
    public void update(Observable obs, Object x) {
        //redraw my clock’s reading
        draw();};
    void draw(){
        int hour = obs.GetHour();
        int minute = obs.GetMinute();
        int second = obs.GetSecond();
        // draw operation};
    };
```

---
### Facade
expose one API instead of a set of classes
Pros:
- Simpler Interface
- Less Dependence (Weak coupling)
- Easier to change
Cons:
- Access to underlying classes
---
### Mediator
one mediator to rule them all
Pros:
- Central Control
- Easier Communications
- Better reuseability
Cons:
- Can be slower
- Single point of failure
- Can get complicated
---
### Model-View-Controller (MVC)
- Model (the core)
- Controller
- View (display info)
Pros:
- Decoupled
- Flexible and Reusable
Cons:
- Complex

